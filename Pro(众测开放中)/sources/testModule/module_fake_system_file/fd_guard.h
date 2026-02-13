#pragma once
#include <unistd.h>

struct fd_guard {
    int fd = -1;

    fd_guard() = default;
    explicit fd_guard(int f) : fd(f) {}

    fd_guard(const fd_guard&) = delete;
    fd_guard& operator=(const fd_guard&) = delete;

    fd_guard(fd_guard&& o) noexcept : fd(o.fd) { o.fd = -1; }
    fd_guard& operator=(fd_guard&& o) noexcept {
        if (this != &o) { reset(o.fd); o.fd = -1; }
        return *this;
    }

    ~fd_guard() { reset(-1); }

    int get() const { return fd; }

    int release() { int t = fd; fd = -1; return t; }

    void reset(int f) {
        if (fd >= 0) (void)::close(fd);
        fd = f;
    }
};
