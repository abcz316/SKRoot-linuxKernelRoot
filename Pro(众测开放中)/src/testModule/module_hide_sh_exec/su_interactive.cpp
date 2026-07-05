#include "su_interactive.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>

#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>

SuInteractive::SuInteractive() = default;

SuInteractive::~SuInteractive() {
    stop(true);
}

void SuInteractive::setCloExec(int fd) {
    int flags = ::fcntl(fd, F_GETFD);
    if (flags >= 0) ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

void SuInteractive::safeClose(int& fd) {
    if (fd >= 0) { ::close(fd); fd = -1; }
}

bool SuInteractive::start(std::string_view shell_rc_dir) {
    stop(true); // 支持重复 start：先清理干净
    return startPty_(shell_rc_dir);
}

static void ignore_sighup() {
    struct sigaction sa {};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    ::sigaction(SIGHUP, &sa, nullptr);
}

void SuInteractive::setupShellPromptEnv_(std::string_view rc_dir) {
    if (rc_dir.empty()) return;

    std::string dir(rc_dir);

    // 去掉末尾多余的 /
    while (dir.size() > 1 && dir.back() == '/') {
        dir.pop_back();
    }

    std::string rc_path = dir + "/.skroot_mkshrc";

    const char* old_env = ::getenv("ENV");

    // 避免 ENV 已经指向自己时递归 source 自己
    if (old_env && *old_env && rc_path != old_env) {
        ::setenv("SKROOT_ORIG_ENV", old_env, 1);
    } else {
        ::unsetenv("SKROOT_ORIG_ENV");
    }

    int fd = ::open(rc_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        const char* rc =
            "if [ -n \"$SKROOT_ORIG_ENV\" ] && [ -r \"$SKROOT_ORIG_ENV\" ]; then\n"
            "  . \"$SKROOT_ORIG_ENV\"\n"
            "fi\n"
            "unset SKROOT_ORIG_ENV\n"
            "PS1='# '\n"
            "PS2='> '\n"
            "PROMPT='# '\n";

        ssize_t left = static_cast<ssize_t>(::strlen(rc));
        const char* p = rc;

        while (left > 0) {
            ssize_t n = ::write(fd, p, static_cast<size_t>(left));
            if (n > 0) {
                p += n;
                left -= n;
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }

        ::close(fd);
        ::chmod(rc_path.c_str(), 0600);

        ::setenv("ENV", rc_path.c_str(), 1);
    }

    ::setenv("PS1", "# ", 1);
    ::setenv("PS2", "> ", 1);
    ::setenv("PROMPT", "# ", 1);
}


bool SuInteractive::startPty_(std::string_view shell_rc_dir) {
    int master = ::posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) {
        return false;
    }
    setCloExec(master);

    if (::grantpt(master) != 0) {
        ::close(master);
        return false;
    }

    if (::unlockpt(master) != 0) {
        ::close(master);
        return false;
    }

    char slave_name[128] = {};
    if (::ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        ::close(master);
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(master);
        return false;
    }

    if (pid == 0) {
        // child: 新建 session，并把 slave pty 设成 controlling tty
        ::setsid();

        int slave = ::open(slave_name, O_RDWR);
        if (slave < 0) {
            _exit(120);
        }

        (void)::ioctl(slave, TIOCSCTTY, 0);

        ::dup2(slave, STDIN_FILENO);
        ::dup2(slave, STDOUT_FILENO);
        ::dup2(slave, STDERR_FILENO);

        if (slave > STDERR_FILENO) {
            ::close(slave);
        }
        ::close(master);

        ignore_sighup();

        setupShellPromptEnv_(shell_rc_dir);
        
        const char* argv[] = {"su", nullptr};
        ::execvp("su", (char* const*)argv);

        const char* msg = "exec su failed\n";
        ::write(STDERR_FILENO, msg, std::strlen(msg));
        _exit(127);
    }

    // parent：PTY master 是双向 fd。这里 dup 一份，尽量复用原 send/read 结构。
    int master_read = ::dup(master);
    if (master_read < 0) {
        ::kill(pid, SIGKILL);
        ::close(master);
        return false;
    }
    setCloExec(master_read);

    m_pid = pid;
    m_in_w = master;
    m_out_r = master_read;

    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_out.clear();
    }

    m_reader = std::thread([this] { readerLoop_(); });
    return true;
}

void SuInteractive::readerLoop_() {
    // 注意：这里读的是“合并后的输出”
    char buf[4096];
    for (;;) {
        int fd = m_out_r;
        if (fd < 0) break;

        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            std::lock_guard<std::mutex> lk(m_mu);
            m_out.append(buf, static_cast<size_t>(n));
            continue;
        }

        if (n == 0) break;              // EOF
        if (errno == EINTR) continue;   // 被信号打断，继续
        if (errno == EIO) break;        // PTY 对端关闭时常见
        // fd 被关闭/其它错误：退出
        break;
    }

    // reader 线程退出前确保关闭读端
    safeClose(m_out_r);
}

bool SuInteractive::send(const std::string& s) {
    if (m_in_w < 0) return false;

    const char* p = s.data();
    size_t left = s.size();
    while (left) {
        ssize_t n = ::write(m_in_w, p, left);
        if (n > 0) {
            p += n;
            left -= static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool SuInteractive::sendLine(const std::string& line) {
    if (!send(line)) return false;
    if (!line.empty() && line.back() == '\n') return true;
    return send("\n");
}

void SuInteractive::closeInput() {
    // PTY master 被 dup 成 m_in_w/m_out_r 两个 fd。
    // 只关写端不会让对端收到挂断，所以这里一起关闭读端。
    safeClose(m_in_w);
    safeClose(m_out_r);
}

int SuInteractive::wait() {
    if (m_pid <= 0) return -1;

    closeInput();

    int status = 0;
    for (;;) {
        pid_t r = ::waitpid(m_pid, &status, 0);
        if (r > 0) break;
        if (r < 0 && errno == EINTR) continue;
        break;
    }

    if (m_reader.joinable()) m_reader.join();

    pid_t old = m_pid;
    m_pid = -1;

    if (old <= 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

void SuInteractive::stop(bool force) {
    // 先关输入，让对端有机会优雅退出
    closeInput();

    if (m_pid > 0 && force) {
        // 先 SIGTERM，再等一会儿，不行再 SIGKILL
        ::kill(m_pid, SIGTERM);

        for (int i = 0; i < 30; ++i) { // ~300ms
            int status = 0;
            pid_t r = ::waitpid(m_pid, &status, WNOHANG);
            if (r == m_pid) {
                m_pid = -1;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (m_pid > 0) {
            ::kill(m_pid, SIGKILL);
        }
    }

    // 关闭输出读端，确保 reader 线程 read 能退出
    safeClose(m_out_r);

    // 回收线程
    if (m_reader.joinable()) m_reader.join();

    // 如果还没回收进程，这里兜底 waitpid 一下（不阻塞太久）
    if (m_pid > 0) {
        int status = 0;
        (void)::waitpid(m_pid, &status, WNOHANG);
        m_pid = -1;
    }
}

std::string SuInteractive::output() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return m_out;
}

std::string SuInteractive::takeOutput() {
    std::lock_guard<std::mutex> lk(m_mu);
    std::string ret = std::move(m_out);
    m_out.clear();
    return ret;
}

pid_t SuInteractive::get_shell_pid() {
    return m_pid;
}

bool SuInteractive::isShellForeground() const {
    if (m_pid <= 0) return false;

    int fd = m_in_w;
    if (fd < 0) fd = m_out_r;
    if (fd < 0) return false;

    pid_t fg_pgrp = -1;
    if (::ioctl(fd, TIOCGPGRP, &fg_pgrp) != 0) {
        return false;
    }

    pid_t shell_pgrp = ::getpgid(m_pid);
    if (shell_pgrp <= 0) {
        return false;
    }

    return fg_pgrp == shell_pgrp;
}