#pragma once
#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace cg_v2 {
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
    int release() { int t = fd; fd = -1; return t; }
    void reset(int f=-1){ if (fd>=0) ::close(fd); fd=f; }
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
inline bool path_exists(const char* p) { return ::access(p, F_OK) == 0; }

inline bool write_num_newline(const char* path, long num) {
    UniqueFd f(::open(path, O_WRONLY | O_CLOEXEC));
    if (!f) return false;
    char buf[64];
    int m = std::snprintf(buf, sizeof(buf), "%ld\n", num);
    if (m <= 0 || m >= (int)sizeof(buf)) { errno = EOVERFLOW; return false; }
    return write_all(f.get(), buf, (size_t)m);
}

struct Result {
    bool ok{false};
    int  err{0};
};

inline Result migrate_self_to_root() {
    const char* v2_procs = "/sys/fs/cgroup/cgroup.procs";
    Result r{};
    if (!path_exists(v2_procs)) {
        r.err = ENOENT;
        return r;
    }
    pid_t self = ::getpid();
    if (!write_num_newline(v2_procs, (long)self)) {
        r.err = errno;
        return r;
    }
    r.ok = true;
    return r;
}

} // namespace cg_v2