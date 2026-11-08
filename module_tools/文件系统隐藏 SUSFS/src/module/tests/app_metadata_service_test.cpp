#include "app_metadata_service.h"
#include "cJSON.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace app_metadata;
static const std::string icon = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
static std::string digest(char c) { return std::string(64, c); }
static std::string body(bool icons = false) { return std::string("{\"packages\":[\"org.test.app\"],\"includeIcons\":") + (icons ? "true}" : "false}"); }
static std::string row(const std::string& label, char v, bool image) {
    return "{\"package\":\"org.test.app\",\"uid\":10123,\"label\":\"" + label + "\",\"iconPng\":\"" + (image ? icon : "") + "\",\"status\":\"ok\",\"version\":\"" + digest(v) + "\"}";
}
static ProcessResult result(const std::string& rows) { return {true, "{\"locale\":\"zh-CN\",\"apps\":[" + rows + "]}"}; }
static cJSON* parsed(const Reply& response) { auto* out = cJSON_Parse(response.body.c_str()); assert(out); return out; }
static std::string field(const Reply& response, const char* name, int index = 0) {
    auto* root = parsed(response);
    auto* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    auto* rows = cJSON_GetObjectItemCaseSensitive(data, "apps");
    auto* value = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(rows, index), name);
    const std::string out = cJSON_IsString(value) ? value->valuestring : "";
    cJSON_Delete(root); return out;
}
int main() {
    {
        char directory[] = "/tmp/plus-metadata-resource-XXXXXX";
        assert(mkdtemp(directory));
        const std::string resource = std::string(directory) + "/app-metadata.dex";
        const std::string alias = std::string(directory) + "/alias.dex";
        const std::string foreign = std::string(directory) + "/foreign.dex";
        const std::string pipe = std::string(directory) + "/invalid-fifo";
        int fd = open(resource.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
        assert(write(fd, "dex\n", 4) == 4); close(fd); assert(chmod(resource.c_str(), 0777) == 0);
        struct stat st{};
        if (geteuid() == 0) {
            assert(prepareDexResource(resource)); // First-use SDK mode 0777 is normalized before launch.
            assert(stat(resource.c_str(), &st) == 0 && (st.st_mode & 07777) == 0444);
            assert(prepareDexResource(resource)); // Already-normalized installs remain usable.
            assert(symlink(resource.c_str(), alias.c_str()) == 0);
            assert(!prepareDexResource(alias)); assert(unlink(alias.c_str()) == 0);
            assert(link(resource.c_str(), alias.c_str()) == 0);
            assert(!prepareDexResource(alias)); assert(unlink(alias.c_str()) == 0);
            fd = open(foreign.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
            assert(write(fd, "dex\n", 4) == 4); close(fd);
            assert(chmod(foreign.c_str(), 0777) == 0 && chown(foreign.c_str(), 1, static_cast<gid_t>(-1)) == 0);
            assert(!prepareDexResource(foreign));
            assert(stat(foreign.c_str(), &st) == 0 && (st.st_mode & 07777) == 0777); // Never chmod somebody else's file.
            assert(unlink(foreign.c_str()) == 0);
            assert(mkfifo(pipe.c_str(), 0600) == 0); assert(!prepareDexResource(pipe)); assert(unlink(pipe.c_str()) == 0);
        } else {
            assert(!prepareDexResource(resource));
            std::cout << "SKIP root-owned DEX normalization tests: requires root\n";
        }
        assert(unlink(resource.c_str()) == 0 && rmdir(directory) == 0);
    }
    std::atomic<int> calls{0}; char current = 'a';
    Service service([&](const std::string& request) {
        ++calls;
        auto* input = cJSON_Parse(request.c_str()); assert(input);
        const bool image = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(input, "includeIcons"));
        auto* known = cJSON_GetObjectItemCaseSensitive(input, "known");
        auto* old = cJSON_GetObjectItemCaseSensitive(known, "org.test.app");
        const bool unchanged = cJSON_IsString(old) && old->valuestring == digest(current);
        cJSON_Delete(input);
        if (unchanged) return result("{\"package\":\"org.test.app\",\"uid\":10123,\"status\":\"ok\",\"unchanged\":true,\"version\":\"" + digest(current) + "\"}");
        return result(row(current == 'a' ? "应用甲" : "应用乙", current, image));
    });
    assert(field(service.handle(body()), "label") == "应用甲");
    assert(field(service.handle(body(true)), "iconPng") == icon);
    assert(field(service.handle(body(true)), "iconPng") == icon); // confirmed unchanged reuses decoded PNG
    assert(calls == 3); // APK/version is checked on every request; there is no blind permanent cache.
    current = 'b';
    assert(field(service.handle(body()), "label") == "应用乙");
    assert(field(service.handle(body(true)), "iconPng") == icon); // label refresh invalidated old icon version
    for (const auto* invalid : {"{}", "[]", "{\"packages\":[],\"includeIcons\":1}",
             "{\"packages\":[\"org.test;id\"],\"includeIcons\":false}",
             "{\"packages\":[\"org.test\",\"org.test\"],\"includeIcons\":false}",
             "{\"packages\":[\"org.1test\"],\"includeIcons\":false}",
             "{\"packages\":[\"org.test\\u0000trailing\"],\"includeIcons\":false}",
             "{\"packages\":[],\"includeIcons\":false}garbage"}) assert(service.handle(invalid).status == 400);
    std::string many = "{\"packages\":[";
    for (int i = 0; i < 65; ++i) { if (i) many += ','; many += "\"org.test.app" + std::to_string(i) + "\""; }
    many += "],\"includeIcons\":false}"; assert(service.handle(many).status == 400);
    std::string tooManyIcons = "{\"packages\":[";
    for (int i = 0; i < 17; ++i) { if (i) tooManyIcons += ','; tooManyIcons += "\"org.test.app" + std::to_string(i) + "\""; }
    tooManyIcons += "],\"includeIcons\":true}"; assert(service.handle(tooManyIcons).status == 400);
    Service failure([](const std::string&) -> ProcessResult { throw std::runtime_error("helper failure"); });
    assert(field(failure.handle(body()), "status") == "unavailable"); assert(!failure.active());
    Service missing([](const std::string&) { return result("{\"package\":\"org.test.app\",\"status\":\"not_found\"}"); });
    assert(field(missing.handle(body()), "status") == "not_found");
    Service partial([](const std::string&) {
        return result(row("present", 'a', false) + ",{\"package\":\"org.test.missing\",\"status\":\"not_found\"}");
    });
    const auto mixed = partial.handle("{\"packages\":[\"org.test.app\",\"org.test.missing\"],\"includeIcons\":false}");
    assert(field(mixed, "label") == "present" && field(mixed, "status", 1) == "not_found");
    Service wrong([](const std::string&) { return result("{\"package\":\"org.test.other\",\"uid\":0,\"label\":\"wrong\",\"status\":\"ok\"}"); });
    assert(field(wrong.handle(body()), "status") == "unavailable");
    Service invalidIcon([](const std::string&) { return result("{\"package\":\"org.test.app\",\"uid\":10123,\"label\":\"name\",\"iconPng\":\"https://unsafe.invalid/icon\",\"status\":\"ok\",\"version\":\"" + digest('a') + "\"}"); });
    const auto rejected = invalidIcon.handle(body(true));
    assert(field(rejected, "iconPng").empty()); assert(field(rejected, "status") == "unavailable"); assert(field(rejected, "label") == "name");
    std::mutex mutex; std::condition_variable cv; bool entered = false, release = false; std::atomic<int> starts{0};
    Service coalesce([&](const std::string&) {
        ++starts; std::unique_lock<std::mutex> lock(mutex); entered = true; cv.notify_all(); cv.wait(lock, [&] { return release; });
        return result(row("same", 'a', false));
    });
    Reply first, second;
    std::thread one([&] { first = coalesce.handle(body()); });
    { std::unique_lock<std::mutex> lock(mutex); cv.wait(lock, [&] { return entered; }); }
    std::thread two([&] { second = coalesce.handle(body()); });
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    { std::lock_guard<std::mutex> lock(mutex); release = true; } cv.notify_all();
    one.join(); two.join(); assert(starts == 1 && first.body == second.body && !coalesce.active());

    auto copied = runProcess("/bin/cat", {}, {}, "private pipe", std::chrono::milliseconds(1000), 1024);
    assert(copied.success && copied.output == "private pipe");
    auto quiet = runProcess("/bin/sh", {"-c", "printf secret >&2; cat"}, {}, "safe output", std::chrono::milliseconds(1000), 1024);
    assert(quiet.success && quiet.output == "safe output");
    auto bounded = runProcess("/bin/sh", {"-c", "printf 1234567890"}, {}, "", std::chrono::milliseconds(1000), 5);
    assert(!bounded.success && bounded.output.empty());
    const auto began = std::chrono::steady_clock::now();
    auto timeout = runProcess("/bin/sh", {"-c", "sleep 2"}, {}, "", std::chrono::milliseconds(100), 1024);
    assert(!timeout.success && std::chrono::steady_clock::now() - began < std::chrono::seconds(1));
    const int retained = open("/dev/null", O_RDONLY); assert(retained >= 3);
    auto descriptors = runProcess("/bin/sh", {"-c", "if test -e /proc/self/fd/" + std::to_string(retained) + "; then printf leaked; else cat; fi"}, {}, "closed", std::chrono::milliseconds(1000), 1024);
    close(retained); assert(descriptors.success && descriptors.output == "closed");
    auto early = runProcess("/bin/false", {}, {}, std::string(30000, 'x'), std::chrono::milliseconds(1000), 1024);
    assert(!early.success); // SIGPIPE must not kill the WebUI process.
    std::cout << "PASS app metadata: validation, freshness, cache, coalescing, bounded pipes and child cleanup\n";
}
