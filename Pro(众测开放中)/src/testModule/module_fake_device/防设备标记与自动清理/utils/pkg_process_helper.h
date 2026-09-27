#pragma once
#include <string>
#include <string.h>
#include <vector>
#include <set>
#include <chrono>
#include <thread>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include "process_utils.h"

namespace fs = std::filesystem;

static uint64_t read_proc_vm_rss_kb(const fs::path& proc_dir) {
    std::ifstream in(proc_dir / "status");
    if (!in) return 0;

    std::string line;
    while (std::getline(in, line)) {
        // 形如: VmRSS:	  136472 kB
        if (line.rfind("VmRSS:", 0) == 0) {
            const char* p = line.c_str() + 6;
            while (*p == ' ' || *p == '\t') ++p;

            char* end = nullptr;
            unsigned long long kb = std::strtoull(p, &end, 10);
            return static_cast<uint64_t>(kb);
        }
    }
    return 0;
}

static bool is_pkg_running(const std::string& pkg, uint64_t min_rss_kb = 0) {
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

        bool matched = false;
        if (cmd0 == pkg) matched = true;
        else if (cmd0.rfind(pkg, 0) == 0 && cmd0.size() > pkg.size() && cmd0[pkg.size()] == ':') matched = true;

        if (!matched) continue;

        if (min_rss_kb > 0) {
            const uint64_t rss_kb = read_proc_vm_rss_kb(e.path());
            if (rss_kb < min_rss_kb) {
                continue; // 内存太小，彻底忽略
            }
        }

        return true;
    }
    return false;
}

static std::vector<pid_t> find_pids_by_pkg_name(const std::string& pkg) {
    std::vector<pid_t> result;
    if (pkg.empty()) return result;

    const fs::path proc_root = "/proc";
    std::error_code ec;
    if (!fs::exists(proc_root, ec) || ec || !fs::is_directory(proc_root, ec) || ec) {
        return result;
    }

    for (const auto& entry : fs::directory_iterator(proc_root, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_directory(ec) || ec) { ec.clear(); continue; }

        const std::string pid_str = entry.path().filename().string();
        if (!process_utils::is_all_digits(pid_str)) continue;

        const pid_t pid = static_cast<pid_t>(std::atoi(pid_str.c_str()));
        if (pid <= 1) continue;

        // 先看 cmdline
        std::string cmdline;
        if (file_utils::read_text_file((entry.path() / "cmdline").string().c_str(), cmdline)) {
            for (char& c : cmdline) {
                if (c == '\0') c = ' ';
            }

            // 主进程 / 子进程 常见形式：
            // com.xxx.app
            // com.xxx.app:remote
            if (cmdline == pkg || cmdline.rfind(pkg + ":", 0) == 0) {
                result.push_back(pid);
                continue;
            }
        }

        // 再兜底看 /proc/<pid>/comm
        std::string comm;
        if (file_utils::read_text_file((entry.path() / "comm").string().c_str(), comm)) {
            while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r' || comm.back() == '\0')) {
                comm.pop_back();
            }
            if (comm == pkg || comm.rfind(pkg + ":", 0) == 0) {
                result.push_back(pid);
                continue;
            }
        }
    }

    return result;
}

static bool kill_pkg_all_processes_once(const std::string& pkg) {
    std::vector<pid_t> pids = find_pids_by_pkg_name(pkg);
    if (pids.empty()) return true;

    printf("kill_pkg_all_processes_once: pkg=%s pid_count=%zu\n", pkg.c_str(), pids.size());

    bool ok = true;
    for (pid_t pid : pids) {
        if (!process_utils::kill_pid_force(pid)) ok = false;
    }
    return ok;
}

static void kill_pkg_list_until_stopped(const std::set<std::string>& pkgs,
                                        uint64_t min_rss_kb = 0,
                                        int max_rounds = 20,
                                        std::chrono::milliseconds sleep_between = std::chrono::milliseconds(300)) {
    using namespace std::chrono_literals;

    for (int round = 0; round < max_rounds; ++round) {
        bool any_running = false;

        for (const auto& pkg : pkgs) {
            if (pkg.empty()) continue;

            if (is_pkg_running(pkg, min_rss_kb)) {
                any_running = true;
                kill_pkg_all_processes_once(pkg);
            }
        }

        if (!any_running) {
            printf("kill_pkg_list_until_stopped done: all target packages stopped\n");
            return;
        }

        std::this_thread::sleep_for(sleep_between);
    }

    // 最后一轮打印剩余情况
    for (const auto& pkg : pkgs) {
        if (is_pkg_running(pkg, min_rss_kb)) {
            printf("kill_pkg_list_until_stopped still_running: %s\n", pkg.c_str());
        }
    }
}