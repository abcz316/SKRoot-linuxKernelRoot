#include "app_metadata_service.h"
#include "cJSON.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace app_metadata {
namespace {
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;
Json json(cJSON* value) { return Json(value, cJSON_Delete); }
std::string print(const cJSON* value) {
    char* raw = cJSON_PrintUnformatted(value);
    if (!raw) return "{}";
    std::string result(raw); cJSON_free(raw); return result;
}
std::string string(const cJSON* object, const char* name) {
    const auto* value = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(value) ? value->valuestring : "";
}
bool packageName(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    bool first = true;
    for (unsigned char ch : name) {
        if (ch == '.') { if (first) return false; first = true; continue; }
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) { first = false; continue; }
        if (first || !((ch >= '0' && ch <= '9') || ch == '_')) return false;
    }
    return !first;
}
Reply envelope(bool ok, cJSON* data, const char* code = "OK") {
    auto root = json(cJSON_CreateObject());
    cJSON_AddBoolToObject(root.get(), "ok", ok);
    cJSON_AddStringToObject(root.get(), "code", code);
    cJSON_AddStringToObject(root.get(), "message", ok ? "" : "Invalid application metadata request");
    cJSON_AddNumberToObject(root.get(), "errno", 0);
    // This read-only endpoint needs no persistent request identity.
    cJSON_AddStringToObject(root.get(), "requestId", "");
    cJSON_AddItemToObject(root.get(), "data", data ? data : cJSON_CreateNull());
    return {ok ? 200 : 400, print(root.get())};
}
void closeFd(int& fd) { if (fd >= 0) { ::close(fd); fd = -1; } }
struct Pipe {
    int fd[2]{-1, -1};
    ~Pipe() { closeFd(fd[0]); closeFd(fd[1]); }
};
struct BlockSigpipe {
    sigset_t old{}, blocked{};
    bool ready = false, had_pending = false;
    BlockSigpipe() {
        sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE);
        ready = pthread_sigmask(SIG_BLOCK, &blocked, &old) == 0;
        sigset_t pending{};
        if (ready && sigpending(&pending) == 0) had_pending = sigismember(&pending, SIGPIPE) == 1;
    }
    ~BlockSigpipe() {
        if (!ready) return;
        if (!had_pending && !sigismember(&old, SIGPIPE)) {
            sigset_t pending{};
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) { int value = 0; sigwait(&blocked, &value); }
        }
        pthread_sigmask(SIG_SETMASK, &old, nullptr);
    }
};
bool png(const std::string& value) {
    // Base64 PNG signature plus bounded standard alphabet; browsers never get a URI from the helper.
    if (value.size() < 12 || value.size() > 87384 || value.size() % 4 || value.compare(0, 11, "iVBORw0KGgo") != 0) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        unsigned char c = value[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') continue;
        if (c == '=' && i >= value.size() - 2) continue;
        return false;
    }
    return true;
}
bool version(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
} // namespace

ProcessResult runProcess(const std::string& executable, const std::vector<std::string>& arguments,
                         const std::vector<std::string>& environment, const std::string& input,
                         std::chrono::milliseconds timeout, std::size_t max_output) {
    ProcessResult result;
    if (input.size() > 32768 || max_output > 2 * 1024 * 1024 || timeout.count() <= 0) return result;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    Pipe in, out;
    if (pipe2(in.fd, O_CLOEXEC) || pipe2(out.fd, O_CLOEXEC)) return result;
    const int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (nullfd < 0) return result;
    std::vector<char*> argv, envp;
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    for (const auto& variable : environment) envp.push_back(const_cast<char*>(variable.c_str()));
    envp.push_back(nullptr);
    rlimit limits{}; getrlimit(RLIMIT_NOFILE, &limits);
    const int maxfd = limits.rlim_cur == RLIM_INFINITY ? 65536 : static_cast<int>(std::min<rlim_t>(limits.rlim_cur, 1048576));
    const pid_t child = fork();
    if (child < 0) { close(nullfd); return result; }
    if (!child) {
        setpgid(0, 0);
        if (dup2(in.fd[0], STDIN_FILENO) < 0 || dup2(out.fd[1], STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0) _exit(126);
#if defined(__NR_close_range)
        if (syscall(__NR_close_range, 3U, ~0U, 0U) != 0)
#endif
        { for (int fd = 3; fd < maxfd; ++fd) close(fd); }
        sigset_t unblocked; sigemptyset(&unblocked); sigaddset(&unblocked, SIGPIPE); sigprocmask(SIG_UNBLOCK, &unblocked, nullptr);
        execve(executable.c_str(), argv.data(), envp.data());
        _exit(127);
    }
    close(nullfd); closeFd(in.fd[0]); closeFd(out.fd[1]); setpgid(child, child);
    fcntl(in.fd[1], F_SETFL, fcntl(in.fd[1], F_GETFL, 0) | O_NONBLOCK);
    fcntl(out.fd[0], F_SETFL, fcntl(out.fd[0], F_GETFL, 0) | O_NONBLOCK);
    BlockSigpipe block;
    std::size_t sent = 0;
    bool eof = false, exited = false, failed = false;
    int status = 0;
    while (!failed && !(eof && exited)) {
        if (std::chrono::steady_clock::now() >= deadline) { failed = true; break; }
        if (sent == input.size()) closeFd(in.fd[1]);
        pollfd pollers[2]{{out.fd[0], static_cast<short>(POLLIN | POLLHUP), 0}, {in.fd[1], POLLOUT, 0}};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        const int wait = static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(remaining, 25)));
        const int polled = poll(pollers, 2, wait);
        if (polled < 0 && errno != EINTR) { failed = true; break; }
        if (in.fd[1] >= 0 && (pollers[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            const ssize_t count = write(in.fd[1], input.data() + sent, input.size() - sent);
            if (count > 0) sent += static_cast<std::size_t>(count);
            else if (count < 0 && errno != EINTR && errno != EAGAIN) { failed = true; break; }
        }
        if (out.fd[0] >= 0 && (pollers[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            std::array<char, 8192> buffer{};
            for (;;) {
                const ssize_t count = read(out.fd[0], buffer.data(), buffer.size());
                if (count > 0) {
                    if (result.output.size() + static_cast<std::size_t>(count) > max_output) { failed = true; break; }
                    result.output.append(buffer.data(), static_cast<std::size_t>(count));
                } else if (!count) { eof = true; closeFd(out.fd[0]); break; }
                else if (errno == EINTR) continue;
                else if (errno == EAGAIN) break;
                else { failed = true; break; }
            }
        }
        if (!exited) {
            const auto value = waitpid(child, &status, WNOHANG);
            if (value == child) exited = true;
            else if (value < 0 && errno != EINTR) { failed = true; break; }
        }
    }
    if (failed) { kill(-child, SIGKILL); kill(child, SIGKILL); }
    if (!exited) { while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    result.success = !failed && sent == input.size() && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!result.success) result.output.clear();
    return result;
}

struct Service::Flight {
    std::condition_variable ready;
    bool done = false;
    Reply reply;
};
Service::Service(Runner runner) : m_runner(std::move(runner)) {}
void Service::configure(const std::string& dex_path, std::function<bool()> initialize) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dex_path = dex_path; m_initialize = std::move(initialize); m_cache.clear();
}
bool Service::active() const { std::lock_guard<std::mutex> lock(m_mutex); return !m_flights.empty(); }
bool prepareDexResource(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat before{}, after{};
    // The SDK may extract even non-executable resources with mode 0777. Only
    // normalize the configured module resource after validating its identity;
    // do not make the SDK's extraction mode a permanent first-use failure.
    const bool valid = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_uid == 0 && before.st_nlink == 1
        && before.st_size > 0 && before.st_size <= 1024 * 1024;
    const bool ready = valid && fchmod(fd, 0444) == 0 && fstat(fd, &after) == 0
        && S_ISREG(after.st_mode) && after.st_uid == 0 && after.st_nlink == 1
        && after.st_dev == before.st_dev && after.st_ino == before.st_ino && after.st_size == before.st_size
        && (after.st_mode & 07777) == 0444;
    close(fd);
    return ready;
}
ProcessResult Service::run(const std::string& input) {
    if (m_runner) return m_runner(input);
    if (m_initialize && !m_initialize()) return {};
    if (!prepareDexResource(m_dex_path)) return {};
    std::vector<std::string> environment;
    for (char** value = environ; value && *value; ++value) if (std::strncmp(*value, "CLASSPATH=", 10) != 0) environment.emplace_back(*value);
    environment.push_back("CLASSPATH=" + m_dex_path);
    return runProcess("/system/bin/app_process", {"/system/bin", "PlusAppMetadata"}, environment, input,
                      std::chrono::milliseconds(5000), 1536 * 1024);
}

Reply Service::handle(const std::string& body) {
    if (body.size() > 32768 || body.find('\0') != std::string::npos || body.find("\\u0000") != std::string::npos) return envelope(false, nullptr, "INVALID_APP_METADATA");
    auto request = json(cJSON_ParseWithLengthOpts(body.c_str(), body.size() + 1, nullptr, true));
    if (!cJSON_IsObject(request.get())) return envelope(false, nullptr, "INVALID_APP_METADATA");
    auto* packages = cJSON_GetObjectItemCaseSensitive(request.get(), "packages");
    auto* icons_value = cJSON_GetObjectItemCaseSensitive(request.get(), "includeIcons");
    if (!cJSON_IsArray(packages) || !cJSON_IsBool(icons_value)) return envelope(false, nullptr, "INVALID_APP_METADATA");
    const bool icons = cJSON_IsTrue(icons_value);
    if (cJSON_GetArraySize(packages) > (icons ? 16 : 64)) return envelope(false, nullptr, "INVALID_APP_METADATA");
    std::vector<std::string> names;
    std::set<std::string> seen;
    for (const cJSON* item = packages->child; item; item = item->next) {
        if (!cJSON_IsString(item) || !packageName(item->valuestring) || !seen.insert(item->valuestring).second) return envelope(false, nullptr, "INVALID_APP_METADATA");
        names.emplace_back(item->valuestring);
    }
    // Identical requests coalesce; return order follows the requested package order.
    std::string key = icons ? "icons" : "labels";
    for (const auto& name : names) { key += '\n'; key += name; }
    auto unavailable = [&]() {
        auto data = json(cJSON_CreateObject()); auto* apps = cJSON_AddArrayToObject(data.get(), "apps");
        for (const auto& name : names) {
            auto* row = cJSON_CreateObject(); cJSON_AddItemToArray(apps, row);
            cJSON_AddStringToObject(row, "package", name.c_str()); cJSON_AddNumberToObject(row, "uid", -1);
            for (const auto* field : {"label", "iconPng", "version"}) cJSON_AddStringToObject(row, field, "");
            cJSON_AddStringToObject(row, "status", "unavailable");
        }
        cJSON_AddStringToObject(data.get(), "locale", ""); return envelope(true, data.release());
    };
    if (names.empty()) return unavailable();
    std::map<std::string, Entry> cached;
    std::shared_ptr<Flight> flight;
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        const auto existing = m_flights.find(key);
        if (existing != m_flights.end()) {
            flight = existing->second;
            if (!flight->ready.wait_for(lock, std::chrono::seconds(5), [&] { return flight->done; })) return unavailable();
            return flight->reply;
        }
        if (m_flights.size() >= 2) return unavailable();
        flight = std::make_shared<Flight>(); m_flights[key] = flight;
        for (const auto& name : names) {
            const auto value = m_cache.find(name);
            if (value != m_cache.end() && value->second.status == "ok" && (!icons || !value->second.icon.empty())) cached.insert(*value);
        }
    }
    Reply response = unavailable();
    try {
        auto input = json(cJSON_CreateObject()); auto* input_names = cJSON_AddArrayToObject(input.get(), "packages");
        for (const auto& name : names) cJSON_AddItemToArray(input_names, cJSON_CreateString(name.c_str()));
        cJSON_AddBoolToObject(input.get(), "includeIcons", icons);
        auto* known = cJSON_AddObjectToObject(input.get(), "known");
        for (const auto& [name, entry] : cached) cJSON_AddStringToObject(known, name.c_str(), entry.version.c_str());
        const auto result = run(print(input.get()));
        if (result.success && result.output.size() <= 1536 * 1024 && result.output.find('\0') == std::string::npos) {
            auto parsed = json(cJSON_ParseWithLengthOpts(result.output.c_str(), result.output.size() + 1, nullptr, true));
            auto* rows = cJSON_GetObjectItemCaseSensitive(parsed.get(), "apps");
            const auto locale = string(parsed.get(), "locale");
            if (cJSON_IsArray(rows) && cJSON_GetArraySize(rows) == static_cast<int>(names.size()) && locale.size() <= 256) {
                std::map<std::string, Entry> entries;
                for (const cJSON* row = rows->child; row; row = row->next) {
                    const auto name = string(row, "package");
                    if (!seen.count(name) || entries.count(name)) continue;
                    Entry entry{name, "", "", "unavailable", "", -1};
                    const auto state = string(row, "status");
                    if (state == "not_found") { entry.status = state; entries[name] = entry; continue; }
                    const auto ver = string(row, "version");
                    const auto* uid = cJSON_GetObjectItemCaseSensitive(row, "uid");
                    const bool valid_uid = cJSON_IsNumber(uid) && std::isfinite(uid->valuedouble) && uid->valuedouble >= 0 && uid->valuedouble <= 2147483647 && uid->valuedouble == std::floor(uid->valuedouble);
                    if (state == "ok" && version(ver) && valid_uid) {
                        const auto old = cached.find(name);
                        if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(row, "unchanged")) && old != cached.end() && old->second.version == ver && old->second.uid == uid->valueint) entry = old->second;
                        else {
                            auto label = string(row, "label"); auto icon = string(row, "iconPng");
                            if (!label.empty() && label.size() <= 2048 && (!icons || png(icon))) entry = {name, label, icons ? icon : "", "ok", ver, uid->valueint};
                        }
                    }
                    // Preserve a usable label when just its icon could not be decoded.
                    if (entry.status != "ok" && valid_uid) {
                        auto label = string(row, "label");
                        if (!label.empty() && label.size() <= 2048) { entry.label = label; entry.uid = uid->valueint; entry.version = ver; }
                    }
                    entries[name] = entry;
                }
                auto data = json(cJSON_CreateObject()); auto* apps = cJSON_AddArrayToObject(data.get(), "apps");
                cJSON_AddStringToObject(data.get(), "locale", locale.c_str());
                std::lock_guard<std::mutex> lock(m_mutex);
                for (const auto& name : names) {
                    Entry entry{name, "", "", "unavailable", "", -1};
                    const auto found = entries.find(name); if (found != entries.end()) entry = found->second;
                    if (entry.status == "ok") {
                        auto old = m_cache.find(name);
                        if (!icons && old != m_cache.end() && old->second.version == entry.version) entry.icon = old->second.icon;
                        m_cache[name] = entry;
                    } else m_cache.erase(name);
                    auto* row = cJSON_CreateObject(); cJSON_AddItemToArray(apps, row);
                    cJSON_AddStringToObject(row, "package", name.c_str()); cJSON_AddNumberToObject(row, "uid", entry.uid);
                    cJSON_AddStringToObject(row, "label", entry.label.c_str()); cJSON_AddStringToObject(row, "iconPng", icons ? entry.icon.c_str() : "");
                    cJSON_AddStringToObject(row, "status", entry.status.c_str()); cJSON_AddStringToObject(row, "version", entry.version.c_str());
                }
                // Avoid retaining an unbounded inventory across installs and uninstalls.
                while (m_cache.size() > 2048) m_cache.erase(m_cache.begin());
                response = envelope(true, data.release());
            }
        }
    } catch (...) { /* Metadata is optional presentation; keep the rest of the UI usable. */ }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        flight->reply = response; flight->done = true; m_flights.erase(key);
    }
    flight->ready.notify_all();
    return response;
}
} // namespace app_metadata
