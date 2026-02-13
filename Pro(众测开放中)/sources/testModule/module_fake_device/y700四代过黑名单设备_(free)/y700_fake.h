#pragma once
#include <string>
#include <cstring>
#include <cstdio>
#include <errno.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sys/wait.h>
namespace fs = std::filesystem;

static void android_open_url(const std::string& url) {
    std::string cmd = "am start -a android.intent.action.VIEW -d " + url;
    FILE * fp = popen(cmd.c_str(), "r");
    if(fp) pclose(fp);
}

static void run_script(const char* script) {
    const char* sh = "/system/bin/sh";
    char* const argv[] = {
        (char*)sh,
        (char*)script,
        nullptr
    };
    execve(sh, argv, environ);
}

template <class Fn>
static pid_t spawn_delayed_task(unsigned delay_sec, Fn&& fn) {
    using F = std::decay_t<Fn>;
    F f = std::forward<Fn>(fn);

    pid_t pid = ::fork();
    if (pid < 0) {
        std::printf("fork failed: %s\n", std::strerror(errno));
        return -1;
    }
    if (pid == 0) {
        ::sleep(delay_sec);
        f();
        _exit(127);
    }
    return pid;
}

static bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

static bool is_pkg_running(const std::string& pkg) {
    std::error_code ec;
    for (fs::directory_iterator it("/proc", fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::directory_iterator(); it.increment(ec)) {

        const auto& e = *it;
        const std::string name = e.path().filename().string();
        if (name.empty() || name[0] < '0' || name[0] > '9') continue;

        std::ifstream in(e.path() / "cmdline", std::ios::binary);
        if (!in) continue;

        std::string cmd0;
        std::getline(in, cmd0, '\0');
        if (cmd0.empty()) continue;

        if (cmd0 == pkg) return true;
        if (cmd0.rfind(pkg, 0) == 0 && cmd0.size() > pkg.size() && cmd0[pkg.size()] == ':') return true;
    }
    return false;
}
