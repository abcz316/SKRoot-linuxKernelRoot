#include "file_broker.h"
#include "list_dir_helper.h"
#include "../../../kernel/skp_sequential.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace file_manager {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::uint32_t kMagic = 0x50464d31;
constexpr std::size_t kMaxBody = 4 * 1024 * 1024, kMaxReply = 16 * 1024 * 1024;
struct Request { std::uint32_t magic, path_bytes, body_bytes; };
struct Response { std::uint32_t magic, status, body_bytes; };
// pthread_atfork uses only async-signal-safe close. Forked installers, shells
// and watchdogs must not keep the broker transport alive.
std::atomic<int> inherited_channel{-1};
// The broker child owns the only manager registration.  It must not leak into
// archive/text worker children created by FileManagerApi.
std::atomic<int> manager_identity_fd{-1};
static_assert(std::atomic<int>::is_always_lock_free);
std::once_flag atfork_once;
int atfork_error=0;
void child_fds() {
    const int channel=inherited_channel.exchange(-1, std::memory_order_relaxed);
    if (channel >= 0) ::close(channel);
    const int manager=manager_identity_fd.exchange(-1, std::memory_order_relaxed);
    if (manager >= 0) ::close(manager);
}
int register_manager() {
    const int fd = ::open(SKP_SEQUENTIAL_NODE, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const skp_sequential_header header{
        SKP_SEQUENTIAL_MAGIC, SKP_SEQUENTIAL_VERSION,
        static_cast<skp_subject_u32>(sizeof(skp_sequential_header)),
        SKP_SEQ_REGISTER_MANAGER, 0, 0};
    if (::write(fd, &header, sizeof(header)) != static_cast<ssize_t>(sizeof(header))) {
        ::close(fd); return -1;
    }
    manager_identity_fd.store(fd, std::memory_order_release);
    return fd;
}
bool transfer(int fd, void* bytes, std::size_t count, bool writing, Clock::time_point deadline) {
    auto* data = static_cast<char*>(bytes);
    while (count) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (ms <= 0) return false;
        pollfd item{fd, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
        const auto ready = ::poll(&item, 1, static_cast<int>(ms));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || !(item.revents & item.events)) return false;
        const auto n = writing ? ::send(fd, data, count, MSG_NOSIGNAL | MSG_DONTWAIT) : ::recv(fd, data, count, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return false;
        data += n; count -= static_cast<std::size_t>(n);
    }
    return true;
}
ApiReply failure(const char* code, const char* message) {
    return makeApiError({code, message, EIO}, 503);
}
ApiReply legacy(const std::string& path, const std::string& body, const std::string& special) {
    if (path == "/listDir") return {200, list_dir_helper::build_list_dir_result_json(body.empty() ? "/" : body, special)};
    if (path == "/checkExecMount") {
        struct statvfs st{};
        if (body.empty() || ::statvfs(body.c_str(), &st)) return {200, "Failed to get filesystem status"};
        return {200, (st.f_flag & ST_NOEXEC) ? "can not exec" : "can exec"};
    }
    if (path == "/checkFileType") {
        std::error_code error;
        if (!std::filesystem::is_regular_file(body, error)) return {200, "not a file"};
        std::ifstream in(body, std::ios::binary); char data[32]{}; in.read(data, sizeof(data));
        if (!in && in.gcount() == 0) return {200, "error reading"};
        if (in.gcount() >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            if (in.gcount() < 20) return {200, "executable_unknown_elf"};
            const auto machine = static_cast<unsigned char>(data[18]) | (static_cast<unsigned char>(data[19]) << 8);
            return {200, machine == 183 ? "executable_arm64" : machine == 40 ? "executable_arm32" : "executable_other_elf"};
        }
        if ((in.gcount() >= 2 && data[0] == '#' && data[1] == '!') ||
            (body.size() >= 3 && body.substr(body.size() - 3) == ".sh")) return {200, "shell_script"};
        return {200, "unknown"};
    }
    return makeApiError({"NOT_FOUND", "Unknown broker file route", ENOENT}, 404);
}
void serve(int fd, const std::string& special) {
    inherited_channel = fd;
    const int nullfd = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd >= 0) { for (int n = 0; n < 3; ++n) ::dup2(nullfd, n); if (nullfd > 2) ::close(nullfd); }
    FileManagerApi api; api.configure(special);
    int manager_fd = register_manager();
    std::atomic<bool> stopped{false}, monitor_done{false};
    std::thread monitor([&] {
        while (!monitor_done.load(std::memory_order_acquire)) {
            short events = 0;
#ifdef POLLRDHUP
            events = POLLRDHUP;
#endif
            pollfd item{fd, events, 0};
            const int ready = ::poll(&item, 1, 50);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || item.revents) {
                stopped.store(true, std::memory_order_release);
                api.requestStop(); ::shutdown(fd, SHUT_RDWR); return;
            }
        }
    });
    for (;;) {
        if (stopped.load(std::memory_order_acquire)) break;
        // Idle EOF is an ordinary parent shutdown, not an operation timeout.
        pollfd idle{fd, POLLIN, 0}; const int rc = ::poll(&idle, 1, 200);
        if (rc < 0 && errno == EINTR) continue;
        if (rc == 0) continue;
        if (rc <= 0 || !(idle.revents & POLLIN)) break;
        auto deadline = Clock::now() + std::chrono::seconds(30); Request request{};
        if (!transfer(fd, &request, sizeof(request), false, deadline) || request.magic != kMagic ||
            !request.path_bytes || request.path_bytes > 256 || request.body_bytes > kMaxBody) break;
        std::string path(request.path_bytes, '\0'), body(request.body_bytes, '\0');
        if (!transfer(fd, path.data(), path.size(), false, deadline) || !transfer(fd, body.data(), body.size(), false, deadline)) break;
        ApiReply reply;
        // The daemon may finish loading the LKM after this broker was forked.
        // A later ordinary request can acquire the missing registration; no
        // background retry loop or cross-module discovery is needed.
        if (manager_fd < 0) manager_fd = register_manager();
        if (path == "@shutdown") { api.requestStop(); api.shutdown(); reply = {200, "closed"}; }
        else if (path == "@active") reply = {200, api.isJobActive() ? "1" : "0"};
        else if (path == "/api/files/manager/status") {
            reply = {200, std::string("{\"ok\":true,\"state\":\"") +
                (manager_fd >= 0 ? "ready" : "unavailable") + "\",\"pid\":" +
                std::to_string(::getpid()) + "}"};
        }
        else if (path.rfind("/api/files/", 0) == 0) reply = api.handle(path, body);
        else reply = legacy(path, body, special);
        if (reply.body.size() > kMaxReply) reply = failure("FILE_BROKER_RESPONSE_TOO_LARGE", "文件结果过大。");
        Response response{kMagic, static_cast<std::uint32_t>(reply.status), static_cast<std::uint32_t>(reply.body.size())};
        deadline = Clock::now() + std::chrono::seconds(30);
        if (!transfer(fd, &response, sizeof(response), true, deadline) || !transfer(fd, reply.body.data(), reply.body.size(), true, deadline) || path == "@shutdown") break;
    }
    api.requestStop(); api.shutdown();
    monitor_done.store(true,std::memory_order_release);monitor.join();
    manager_identity_fd.store(-1, std::memory_order_release);
    if (manager_fd >= 0) ::close(manager_fd);
    inherited_channel = -1; ::close(fd);
    ::_exit(0);
}
}
FileBroker::~FileBroker() { shutdown(); }
bool FileBroker::start(const std::string& special) {
    std::lock_guard<std::mutex> lock(mutex_); if (child_ > 0) return false;
    std::call_once(atfork_once, [] { atfork_error=::pthread_atfork(nullptr,nullptr,child_fds); });
    if (atfork_error) return false;
    int sockets[2]; if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)) return false;
    const auto pid = ::fork();
    if (pid < 0) { ::close(sockets[0]); ::close(sockets[1]); return false; }
    if (pid == 0) { ::close(sockets[0]); serve(sockets[1], special); }
    ::close(sockets[1]); fd_ = sockets[0]; child_ = pid; inherited_channel = fd_;
    return true;
}
ApiReply FileBroker::handle(const std::string& path, const std::string& body) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ < 0 || path.empty() || path.size() > 256 || body.size() > kMaxBody)
        return failure("FILE_BROKER_UNAVAILABLE", "文件服务已停止，请重新打开 WebUI。");
    const auto deadline = Clock::now() + std::chrono::seconds(30);
    Request request{kMagic, static_cast<std::uint32_t>(path.size()), static_cast<std::uint32_t>(body.size())};
    Response response{};
    bool ok = transfer(fd_, &request, sizeof(request), true, deadline) &&
        transfer(fd_, const_cast<char*>(path.data()), path.size(), true, deadline) &&
        transfer(fd_, const_cast<char*>(body.data()), body.size(), true, deadline) &&
        transfer(fd_, &response, sizeof(response), false, deadline) && response.magic == kMagic &&
        response.body_bytes <= kMaxReply && response.status >= 100 && response.status <= 599;
    std::string result(ok ? response.body_bytes : 0, '\0');
    if (ok) ok = transfer(fd_, result.data(), result.size(), false, deadline);
    if (!ok) {
        ::close(fd_); inherited_channel = fd_ = -1;
        return failure("FILE_BROKER_OUTCOME_UNKNOWN", "文件操作结果未知，请确认文件状态后重新打开 WebUI，勿重复提交。");
    }
    return {static_cast<int>(response.status), std::move(result)};
}
bool FileBroker::isJobActive() {
    const auto reply = handle("@active", ""); return reply.status != 200 || reply.body != "0";
}
void FileBroker::shutdown() {
    (void)handle("@shutdown", "");
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ >= 0) ::close(fd_); inherited_channel = fd_ = -1;
    if (child_ <= 0) return;
    int status = 0;
    for (int n = 0; n < 100; ++n) {
        const auto result = ::waitpid(child_, &status, WNOHANG);
        if (result == child_ || (result < 0 && errno == ECHILD)) { child_ = -1; return; }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    (void)::kill(child_, SIGKILL);
    while (::waitpid(child_, &status, 0) < 0 && errno == EINTR) {}
    child_ = -1;
}
}


