#include "pipe_su_interactive.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {

// Record Separator + 固定字符串 + Unit Separator。
// reader 会把这段 marker 吃掉，对外只保留正常的 "# "。
constexpr std::string_view kReadyMarker = "\x1e" "SKROOT_READY" "\x1f";
constexpr std::string_view kPromptText  = "# ";

bool waitPidBlocking(pid_t pid, int& status) {
    for (;;) {
        pid_t r = ::waitpid(pid, &status, 0);
        if (r == pid) return true;
        if (r < 0 && errno == EINTR) continue;
        return false;
    }
}

} // namespace

PipeSuInteractive::PipeSuInteractive() = default;

PipeSuInteractive::~PipeSuInteractive() {
    stop(true);
}

bool PipeSuInteractive::makePipe(int p[2]) {
    if (::pipe(p) != 0) return false;
    setCloExec(p[0]);
    setCloExec(p[1]);
    return true;
}

void PipeSuInteractive::setCloExec(int fd) {
    int flags = ::fcntl(fd, F_GETFD);
    if (flags >= 0) {
        (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

void PipeSuInteractive::safeClose(int& fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

void PipeSuInteractive::setupShellPromptEnv_(std::string_view rc_dir) {
    // Pipe 没有 controlling tty，所以必须强制 sh -i，并通过特殊 PS1 marker
    // 判断 shell 什么时候重新回到命令输入状态。
    std::string prompt;
    prompt.reserve(kReadyMarker.size() + kPromptText.size());
    prompt.append(kReadyMarker);
    prompt.append(kPromptText);

    // 没指定 rc 目录时，不加载外部 ENV，避免外部 rc 再次覆盖 PS1。
    if (rc_dir.empty()) {
        ::unsetenv("ENV");
        ::unsetenv("SKROOT_ORIG_ENV");
        ::setenv("PS1", prompt.c_str(), 1);
        ::setenv("PS2", "> ", 1);
        ::setenv("PROMPT", prompt.c_str(), 1);
        return;
    }

    std::string dir(rc_dir);
    while (dir.size() > 1 && dir.back() == '/') {
        dir.pop_back();
    }

    const std::string rc_path = dir + "/.skroot_mkshrc";
    const char* old_env = ::getenv("ENV");

    // 让生成的 rc 可以先 source 原本的 ENV，再覆盖 prompt。
    if (old_env && *old_env && rc_path != old_env) {
        ::setenv("SKROOT_ORIG_ENV", old_env, 1);
    } else {
        ::unsetenv("SKROOT_ORIG_ENV");
    }
    int fd = ::open(rc_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        std::string rc;
        rc.reserve(256);
        rc += "if [ -n \"$SKROOT_ORIG_ENV\" ] && [ -r \"$SKROOT_ORIG_ENV\" ]; then\n";
        rc += "  . \"$SKROOT_ORIG_ENV\"\n";
        rc += "fi\n";
        rc += "unset SKROOT_ORIG_ENV\n";
        rc += "PS1='";
        rc.append(kReadyMarker);
        rc += "# '\n";
        rc += "PS2='> '\n";
        rc += "PROMPT=\"$PS1\"\n";

        const char* p = rc.data();
        size_t left = rc.size();
        while (left > 0) {
            ssize_t n = ::write(fd, p, left);
            if (n > 0) {
                p += n;
                left -= static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }

        ::close(fd);
        (void)::chmod(rc_path.c_str(), 0600);
        ::setenv("ENV", rc_path.c_str(), 1);
    } else {
        // rc 文件创建失败时仍保证 marker 可用。
        ::unsetenv("ENV");
        ::unsetenv("SKROOT_ORIG_ENV");
    }

    ::setenv("PS1", prompt.c_str(), 1);
    ::setenv("PS2", "> ", 1);
    ::setenv("PROMPT", prompt.c_str(), 1);
}

bool PipeSuInteractive::start(std::string_view shell_rc_dir) {
    stop(true); // 支持重复 start：先清理干净

    m_shell_ready.store(false, std::memory_order_release);
    m_parse_pending.clear();

    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_out.clear();
    }

    int in_p[2]{-1, -1};
    int out_p[2]{-1, -1};

    if (!makePipe(in_p) || !makePipe(out_p)) {
        if (in_p[0] >= 0) ::close(in_p[0]);
        if (in_p[1] >= 0) ::close(in_p[1]);
        if (out_p[0] >= 0) ::close(out_p[0]);
        if (out_p[1] >= 0) ::close(out_p[1]);
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(in_p[0]);
        ::close(in_p[1]);
        ::close(out_p[0]);
        ::close(out_p[1]);
        return false;
    }

    if (pid == 0) {
        // child: stdin/stdout/stderr 全部接到 pipe。
        if (::dup2(in_p[0], STDIN_FILENO) < 0 ||
            ::dup2(out_p[1], STDOUT_FILENO) < 0 ||
            ::dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
            _exit(126);
        }

        ::close(in_p[0]);
        ::close(in_p[1]);
        ::close(out_p[0]);
        ::close(out_p[1]);

        setupShellPromptEnv_(shell_rc_dir);

        const char* argv[] = {"su", nullptr};
        ::execvp("su", (char* const*)argv);

        const char* msg = "exec su failed\n";
        (void)::write(STDERR_FILENO, msg, std::strlen(msg));
        _exit(127);
    }

    // parent
    m_pid = pid;

    ::close(in_p[0]);
    ::close(out_p[1]);

    m_in_w = in_p[1];
    m_out_r = out_p[0];

    m_reader = std::thread([this] { readerLoop_(); });
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_out += kPromptText;
        m_out.push_back('\n');
    }
    return true;
}

void PipeSuInteractive::consumeOutput_(const char* data, size_t size) {
    m_parse_pending.append(data, size);

    for (;;) {
        const size_t pos = m_parse_pending.find(kReadyMarker);
        if (pos != std::string::npos) {
            // marker 前面的内容全部是正常输出。
            if (pos != 0) {
                std::lock_guard<std::mutex> lk(m_mu);
                m_out.append(m_parse_pending.data(), pos);
            }

            // marker 本身不暴露给调用方。
            m_parse_pending.erase(0, pos + kReadyMarker.size());

            // 看到 PS1 marker = shell 已经重新进入命令输入状态。
            m_shell_ready.store(true, std::memory_order_release);
            continue;
        }

        // 没找到完整 marker 时，要保留尾部可能存在的 marker 前缀，
        // 防止 read() 刚好把 marker 拆成两段。
        size_t keep = 0;
        const size_t max_keep = std::min(m_parse_pending.size(), kReadyMarker.size() - 1);

        for (size_t n = max_keep; n > 0; --n) {
            const size_t start = m_parse_pending.size() - n;
            const std::string_view tail(m_parse_pending.data() + start, n);
            if (tail == kReadyMarker.substr(0, n)) {
                keep = n;
                break;
            }
        }

        const size_t flush_size = m_parse_pending.size() - keep;
        if (flush_size != 0) {
            {
                std::lock_guard<std::mutex> lk(m_mu);
                m_out.append(m_parse_pending.data(), flush_size);
            }
            m_parse_pending.erase(0, flush_size);
        }
        break;
    }
}

void PipeSuInteractive::flushPendingOutput_() {
    if (m_parse_pending.empty()) return;

    std::lock_guard<std::mutex> lk(m_mu);
    m_out.append(m_parse_pending);
    m_parse_pending.clear();
}

void PipeSuInteractive::readerLoop_() {
    char buf[4096];

    for (;;) {
        const int fd = m_out_r;
        if (fd < 0) break;

        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            consumeOutput_(buf, static_cast<size_t>(n));
            continue;
        }

        if (n == 0) break;            // EOF
        if (errno == EINTR) continue; // 被信号打断，继续
        break;
    }

    flushPendingOutput_();
    m_shell_ready.store(false, std::memory_order_release);

    // reader 线程退出前确保关闭读端。
    safeClose(m_out_r);
}

bool PipeSuInteractive::send(const std::string& s) {
    if (m_in_w < 0) return false;

    // 一旦提交了完整命令，shell 在再次输出 prompt marker 前都视为 busy。
    // 必须在 write() 前置 false，避免极短命令已经返回 prompt 后又被覆盖成 false。
    if (s.find('\n') != std::string::npos) {
        m_shell_ready.store(false, std::memory_order_release);
    }

    const char* p = s.data();
    size_t left = s.size();

    while (left > 0) {
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

bool PipeSuInteractive::sendLine(const std::string& line) {
    if (!line.empty()) {
        std::lock_guard<std::mutex> lk(m_mu);
        m_out.append(kPromptText);
        m_out.append(line);
        m_out.push_back('\n');
    }
    if (!send(line)) return false;
    if (!line.empty() && line.back() == '\n') return true;
    return send("\n");
}

void PipeSuInteractive::closeInput() {
    safeClose(m_in_w);
}

int PipeSuInteractive::wait() {
    if (m_pid <= 0) return -1;

    closeInput();

    const pid_t pid = m_pid;
    int status = 0;
    const bool ok = waitPidBlocking(pid, status);

    if (m_reader.joinable()) {
        m_reader.join();
    }

    m_pid = -1;
    m_shell_ready.store(false, std::memory_order_release);

    if (!ok) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

void PipeSuInteractive::stop(bool force) {
    closeInput();
    m_shell_ready.store(false, std::memory_order_release);

    const pid_t pid = m_pid;
    bool reaped = false;

    if (pid > 0 && force) {
        (void)::kill(pid, SIGTERM);

        for (int i = 0; i < 30; ++i) { // ~300ms
            int status = 0;
            pid_t r = ::waitpid(pid, &status, WNOHANG);
            if (r == pid) {
                reaped = true;
                break;
            }
            if (r < 0 && errno == ECHILD) {
                reaped = true;
                break;
            }
            if (r < 0 && errno != EINTR) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (!reaped) {
            (void)::kill(pid, SIGKILL);
            int status = 0;
            reaped = waitPidBlocking(pid, status);
        }
    } else if (pid > 0) {
        // force=false：输入已关闭，正常交互 shell 一般会收到 EOF 后退出。
        int status = 0;
        reaped = waitPidBlocking(pid, status);
    }

    // 子进程被回收后，pipe 写端关闭，reader 会自然收到 EOF。
    if (m_reader.joinable()) {
        m_reader.join();
    }

    safeClose(m_out_r);
    m_pid = -1;
    m_parse_pending.clear();

    (void)reaped;
}

std::string PipeSuInteractive::output() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return m_out;
}

std::string PipeSuInteractive::takeOutput() {
    std::lock_guard<std::mutex> lk(m_mu);
    std::string ret = std::move(m_out);
    m_out.clear();
    return ret;
}

pid_t PipeSuInteractive::get_shell_pid() {
    return m_pid;
}

bool PipeSuInteractive::isShellForeground() const {
    return m_pid > 0 && m_shell_ready.load(std::memory_order_acquire);
}
