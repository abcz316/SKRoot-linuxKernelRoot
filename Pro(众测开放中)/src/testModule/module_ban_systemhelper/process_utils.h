#pragma once
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace process_utils {

// 判断字符串是否全为数字
static inline bool is_all_digits(const char* s) {
    if (s == nullptr || *s == '\0') return false;
    for (const char* p = s; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

// 读取 /proc/<pid>/cmdline 完整内容（含全部参数，参数间以 NUL 分隔）
static inline std::string read_proc_cmdline(pid_t pid) {
    std::ifstream in("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!in) return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// 判断 cmdline 是否命中目标包名：
// 覆盖直接包名 com.xxx.app、子进程 com.xxx.app:remote，以及 "包名:com.xxx.app" 等形式。
static inline bool cmdline_has_pkg(const std::string& cmdline, const std::string& pkg) {
    if (pkg.empty()) return false;
    return cmdline.find(pkg) != std::string::npos;
}

// 强杀进程；pid<=1 或进程已不存在时按成功处理
static bool kill_pid_force(pid_t pid) {
    if (pid <= 1) return false;
    if (::kill(pid, SIGKILL) == 0) return true;
    if (errno == ESRCH) return true; // 已不存在，也算成功
    printf("kill_pid_force failed: pid=%d errno=%d msg=%s\n", pid, errno, std::strerror(errno));
    return false;
}

// 扫描所有进程 cmdline，返回命中目标包名的 PID 列表
static inline std::vector<pid_t> find_pids_by_cmdline_pkg(const std::string& pkg) {
    std::vector<pid_t> pids;
    DIR* dir = ::opendir("/proc");
    if (!dir) return pids;

    struct dirent* ent = nullptr;
    while ((ent = ::readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        if (!is_all_digits(ent->d_name)) continue;

        pid_t pid = static_cast<pid_t>(::atoi(ent->d_name));
        if (pid <= 0) continue;

        if (cmdline_has_pkg(read_proc_cmdline(pid), pkg)) {
            pids.push_back(pid);
        }
    }
    ::closedir(dir);
    return pids;
}

// 杀掉所有 cmdline 命中目标包名的进程
static inline void kill_pkg_processes(const std::string& pkg) {
    std::vector<pid_t> pids = find_pids_by_cmdline_pkg(pkg);
    for (pid_t pid : pids) {
        printf("kill target process: pid=%d pkg=%s\n", pid, pkg.c_str());
        kill_pid_force(pid);
    }
}

// 判断是否仍有进程 cmdline 命中目标包名（包括 "包名:pkg" 形式）
static inline bool pkg_present_in_cmdline(const std::string& pkg) {
    DIR* dir = ::opendir("/proc");
    if (!dir) return true; // 打不开 /proc 时保守返回 true（认为仍存在）

    bool found = false;
    struct dirent* ent = nullptr;
    while ((ent = ::readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        if (!is_all_digits(ent->d_name)) continue;

        pid_t pid = static_cast<pid_t>(::atoi(ent->d_name));
        if (pid <= 0) continue;

        std::string cmdline = read_proc_cmdline(pid);
        if (cmdline_has_pkg(cmdline, pkg)) {
            printf("target package still present: pid=%d cmdline=%s\n", pid, cmdline.c_str());
            found = true;
            break;
        }
    }
    ::closedir(dir);
    return found;
}

} // namespace process_utils
