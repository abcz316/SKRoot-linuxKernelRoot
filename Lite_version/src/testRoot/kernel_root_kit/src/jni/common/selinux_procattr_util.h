#pragma once
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

namespace selinux_procattr {

namespace detail {

inline pid_t gettid_compat() {
#ifdef SYS_gettid
    return static_cast<pid_t>(syscall(SYS_gettid));
#else
    return static_cast<pid_t>(syscall(__NR_gettid));
#endif
}

// 打开本线程的 /proc/.../attr/<attr>
// 优先 thread-self（新内核更推荐），不行再 fallback 到 self/task/<tid>
inline int open_self_attr(const char* attr, int flags) {
    char path[128];

    // 1) /proc/thread-self/attr/<attr>
    snprintf(path, sizeof(path), "/proc/thread-self/attr/%s", attr);
    int fd = open(path, flags | O_CLOEXEC);
    if (fd >= 0) return fd;

    if (errno != ENOENT) return -1;

    // 2) /proc/self/task/<tid>/attr/<attr>
    const pid_t tid = gettid_compat();
    snprintf(path, sizeof(path), "/proc/self/task/%d/attr/%s", static_cast<int>(tid), attr);
    return open(path, flags | O_CLOEXEC);
}

inline int write_attr(const char* attr, const char* con) {
    int fd = open_self_attr(attr, O_WRONLY);
    if (fd < 0) return -1;

    ssize_t rc;
    if (con) {
        const size_t n = strlen(con) + 1; // 写入包含 '\0'
        do { rc = write(fd, con, n); } while (rc < 0 && errno == EINTR);
    } else {
        // “清空/恢复默认”：写 0 字节（别传 nullptr 给 write）
        const char* empty = "";
        do { rc = write(fd, empty, 0); } while (rc < 0 && errno == EINTR);
    }

    const int saved = errno;
    close(fd);
    errno = saved;
    return (rc < 0) ? -1 : 0;
}

inline std::string read_attr(const char* attr) {
    int fd = open_self_attr(attr, O_RDONLY);
    if (fd < 0) return {};

    std::string out;
    char buf[256];

    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out.append(buf, buf + n);
    }

    const int saved = errno;
    close(fd);
    errno = saved;

    // 去掉末尾可能的 '\0' 或 '\n'
    while (!out.empty() && (out.back() == '\0' || out.back() == '\n')) out.pop_back();
    return out;
}

} // namespace detail

inline int setcon(const char* con) { return detail::write_attr("current", con); }

inline int setexeccon(const char* con) { return detail::write_attr("exec", con); }

inline std::string getcon() { return detail::read_attr("current"); }

inline std::string getexeccon() { return detail::read_attr("exec"); }

} // namespace selinux_procattr
