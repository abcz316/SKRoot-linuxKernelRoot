#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

namespace ns_utils {
bool clone_init_mount_ns() {
    int fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    if (setns(fd, CLONE_NEWNS) < 0) {
        close(fd);
        return false;
    }
    close(fd);
    if (unshare(CLONE_NEWNS) < 0) return false;
    return true;
}
} // namespace ns_utils