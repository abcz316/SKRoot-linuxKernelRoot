#pragma once
#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace cg_v1 {
struct UniqueFd {
    int fd{-1};
    UniqueFd() = default;
    explicit UniqueFd(int f) : fd(f) {}
    ~UniqueFd() { if (fd >= 0) ::close(fd); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& o) noexcept : fd(o.fd) { o.fd = -1; }
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) { if (fd>=0) ::close(fd); fd=o.fd; o.fd=-1; }
        return *this;
    }
    explicit operator bool() const { return fd >= 0; }
    int get() const { return fd; }
};

inline bool write_all(int fd, const char* data, size_t n) {
    const char* p = data;
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= (size_t)w;
    }
    return true;
}
inline bool write_num_newline(const char* path, long num) {
    UniqueFd f(::open(path, O_WRONLY | O_CLOEXEC));
    if (!f) return false;
    char buf[64];
    int m = std::snprintf(buf, sizeof(buf), "%ld\n", num);
    if (m <= 0 || m >= (int)sizeof(buf)) { errno = EOVERFLOW; return false; }
    return write_all(f.get(), buf, (size_t)m);
}
inline bool path_exists(const char* p) { return ::access(p, F_OK) == 0; }

// 迁移结果
struct Result {
    int threads_total{0};
    int cpuset_moved{0};
    int stune_moved{0};
    int err_any{0};
    bool ok() const { return true; }
};

inline int count_self_threads() {
    int total = 0;
    if (DIR* d = ::opendir("/proc/self/task")) {
        while (dirent* e = ::readdir(d)) {
            if (e->d_name[0]=='.') continue;
            char* end=nullptr; long tid = std::strtol(e->d_name, &end, 10);
            if (!end || *end!='\0' || tid<=0) continue;
            ++total;
        }
        ::closedir(d);
    }
    return total;
}

inline int migrate_all_threads_to_tasks(const char* tasks_path) {
    if (!tasks_path || !path_exists(tasks_path)) return 0;
    int moved=0, total=0;
    if (DIR* d = ::opendir("/proc/self/task")) {
        while (dirent* e = ::readdir(d)) {
            if (e->d_name[0]=='.') continue;
            char* end=nullptr; long tid = std::strtol(e->d_name, &end, 10);
            if (!end || *end!='\0' || tid<=0) continue;
            ++total;
            if (write_num_newline(tasks_path, tid)) ++moved;
        }
        ::closedir(d);
    }
    return moved;
}

inline const char* pick_first_existing_cpuset() {
    static const char* C[] = {
        "/dev/cpuset/top-app/tasks",
        "/dev/cpuset/foreground/tasks",
        "/dev/cpuset/system-background/tasks",
        "/dev/cpuset/background/tasks",
        "/dev/cpuset/tasks"
    };
    for (const char* p : C) if (path_exists(p)) return p;
    return nullptr;
}
inline const char* pick_first_existing_stune() {
    static const char* S[] = {
        "/dev/stune/top-app/tasks",
        "/dev/stune/foreground/tasks",
        "/dev/stune/background/tasks",
        "/dev/stune/tasks"
    };
    for (const char* p : S) if (path_exists(p)) return p;
    return nullptr;
}

inline Result migrate_self_threads_v1(const char* cpuset_tasks_path = nullptr,
                                      const char* stune_tasks_path  = nullptr) {
    Result r{};
    r.threads_total = count_self_threads();

    const char* cp = cpuset_tasks_path ? cpuset_tasks_path : pick_first_existing_cpuset();
    const char* sp = stune_tasks_path  ? stune_tasks_path  : pick_first_existing_stune();

    if (cp) {
        int moved = migrate_all_threads_to_tasks(cp);
        r.cpuset_moved = moved;
        if (moved == 0 && r.err_any == 0) r.err_any = errno ? errno : EPERM;
    }
    if (sp) {
        int moved = migrate_all_threads_to_tasks(sp);
        r.stune_moved = moved;
        if (moved == 0 && r.err_any == 0) r.err_any = errno ? errno : EPERM;
    }
    return r;
}

} // namespace cg_v1
