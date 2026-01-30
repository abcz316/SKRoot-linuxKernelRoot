#pragma once
#include <string>
#include <cstring>
#include <cstdio>
#include <errno.h>
#include <type_traits>
#include <utility>
#include <unistd.h>

static std::string run_cmd(const std::string& cmd) {
	std::string cmd_add_err_info = cmd;
	cmd_add_err_info += " 2>&1";
    FILE * fp = popen(cmd_add_err_info.c_str(), "r");
    if(!fp) return {};
    int pip = fileno(fp);

    std::string result;
    while(true) {
        char rbuf[1024] = {0};
        ssize_t r = read(pip, rbuf, sizeof(rbuf));
        if (r == -1 && errno == EAGAIN) continue;
        else if(r > 0) { std::string str_convert(rbuf, r); result += str_convert; }
        else break;
    }
    pclose(fp);
    return result;
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