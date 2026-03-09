#include "su_interactive.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <cstring>
#include <chrono>
#include <thread>

SuInteractive::SuInteractive() = default;

SuInteractive::~SuInteractive() {
    stop(true);
}

bool SuInteractive::makePipe(int p[2]) {
    if (::pipe(p) != 0) return false;
    setCloExec(p[0]);
    setCloExec(p[1]);
    return true;
}

void SuInteractive::setCloExec(int fd) {
    int flags = ::fcntl(fd, F_GETFD);
    if (flags >= 0) ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

void SuInteractive::safeClose(int& fd) {
    if (fd >= 0) { ::close(fd); fd = -1; }
}

bool SuInteractive::start() {
    stop(true); // 支持重复 start：先清理干净

    int in_p[2]{-1,-1};
    int out_p[2]{-1,-1};
    if (!makePipe(in_p) || !makePipe(out_p)) {
        if (in_p[0] >= 0) ::close(in_p[0]);
        if (in_p[1] >= 0) ::close(in_p[1]);
        if (out_p[0] >= 0) ::close(out_p[0]);
        if (out_p[1] >= 0) ::close(out_p[1]);
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(in_p[0]); ::close(in_p[1]);
        ::close(out_p[0]); ::close(out_p[1]);
        return false;
    }

    if (pid == 0) {
        // child: stdin/out/err
        ::dup2(in_p[0], STDIN_FILENO);
        ::dup2(out_p[1], STDOUT_FILENO);
        ::dup2(STDOUT_FILENO, STDERR_FILENO); // stderr 合并到 stdout

        ::close(in_p[0]); ::close(in_p[1]);
        ::close(out_p[0]); ::close(out_p[1]);

        // 只用 su
        const char* argv[] = {"su", nullptr};
        ::execvp("su", (char* const*)argv);

        // exec failed
        const char* msg = "exec su failed\n";
        ::write(STDERR_FILENO, msg, std::strlen(msg));
        _exit(127);
    }

    // parent
    m_pid = pid;

    ::close(in_p[0]);
    ::close(out_p[1]);

    m_in_w  = in_p[1];
    m_out_r = out_p[0];

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
            // 1) 实时打印（你要的“持续读取输出”）
            //    如果你不想默认打印，把下面这行注释掉即可。
            (void)::write(STDOUT_FILENO, buf, static_cast<size_t>(n));

            // 2) 累积到 string（方便你之后一次性取）
            {
                std::lock_guard<std::mutex> lk(m_mu);
                m_out.append(buf, static_cast<size_t>(n));
            }
            continue;
        }

        if (n == 0) break;              // EOF
        if (errno == EINTR) continue;   // 被信号打断，继续
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
    safeClose(m_in_w);
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
