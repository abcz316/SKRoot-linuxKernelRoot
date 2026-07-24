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

extern char** environ;

static void exec_script(const char* script) {
    const char* sh = "/system/bin/sh";
    char* const argv[] = {
        const_cast<char*>(sh),
        const_cast<char*>(script),
        nullptr
    };
    execve(sh, argv, environ);
    // execve 成功不会返回，走到这里说明失败
    perror("execve /system/bin/sh failed");
    _exit(127);
}

static int fork_run_script_and_wait(const char* script) {
    pid_t pid = ::fork();
    if (pid < 0) {
        perror("fork failed");
        return -1;
    }
    if (pid == 0) {
        exec_script(script);
        _exit(127); // 理论上不会走到这里，防御一下
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        perror("waitpid failed");
        return -1;
    }
    return status;
}

template <class Fn>
static pid_t fork_delayed_task(unsigned delay_sec, Fn&& fn) {
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