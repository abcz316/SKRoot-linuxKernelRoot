#pragma once
#include <dirent.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>

#include "random_utils.h"

#ifndef MY_TASK_COMM_LEN
#define MY_TASK_COMM_LEN 16
#endif

namespace process_utils {
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

static bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

static bool kill_pid_force(pid_t pid) {
    if (pid <= 1) return false;

    if (::kill(pid, SIGKILL) == 0) {
        return true;
    }

    if (errno == ESRCH) return true; // 已不存在，也算成功
    printf("kill_pid_force failed: pid=%d errno=%d msg=%s\n", pid, errno, std::strerror(errno));
    return false;
}

static bool is_pid_root(int pid) {
    if (pid <= 0) return false;

    std::ifstream in("/proc/" + std::to_string(pid) + "/status");
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (!line.starts_with("Uid:")) continue;

        std::istringstream iss(line);
        std::string key;
        unsigned int ruid = 0, euid = 0, suid = 0, fsuid = 0;
        if (iss >> key >> ruid >> euid >> suid >> fsuid) {
            return euid == 0;
        }
        return false;
    }

    return false;
}

static std::string reset_random_process_name() {
	std::vector<uint8_t> random_name = random_utils::generate_unique_non_zero_bytes(MY_TASK_COMM_LEN - 1);
	random_name.push_back(0);
	if (prctl(PR_SET_NAME, random_name.data(), 0, 0, 0)) return "";
    char verify_name[MY_TASK_COMM_LEN] = {0};
    if (prctl(PR_GET_NAME, verify_name, 0, 0, 0)) return "";
    if (strncmp(reinterpret_cast<const char*>(random_name.data()), verify_name, MY_TASK_COMM_LEN) != 0) {
        return "";
    }
    return verify_name;
}

} // namespace process_utils