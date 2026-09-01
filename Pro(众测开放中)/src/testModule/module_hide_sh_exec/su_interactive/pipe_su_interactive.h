#pragma once
#include <sys/types.h>

#include <atomic>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "isu_interactive.h"

// pipe 版 su 交互：stderr 合并到 stdout，无 controlling tty。
// 通过隐藏 prompt marker 判断 shell 是否已经重新进入命令输入状态。
class PipeSuInteractive : public ISuInteractive {
public:
    PipeSuInteractive();
    ~PipeSuInteractive() override;

    // 启动 su。
    // 内部强制启动交互式 /system/bin/sh，使 Pipe 模式也会产生 prompt。
    // shell_rc_dir 非空时，会在该目录生成 .skroot_mkshrc；
    // 原 ENV（如果存在）会先被 source，随后覆盖 PS1/PS2/PROMPT。
    bool start(std::string_view shell_rc_dir = {}) override;

    // 发送数据/发送一行（自动补 '\n'）
    bool send(const std::string& s) override;
    bool sendLine(const std::string& line) override;

    // 关闭输入（让对端收到 EOF）
    void closeInput() override;

    // 等待子进程退出（返回 exit code；信号：128+sig；失败 -1）
    int wait() override;

    // 停止并清理：
    // force=false：只关闭输入并等待 shell 自己退出。
    // force=true ：SIGTERM + 短暂等待 + SIGKILL，确保回收。
    void stop(bool force = true) override;

    // 获取累积输出（拷贝）
    std::string output() const override;

    // 取走并清空累积输出（更适合“增量取日志”）
    std::string takeOutput() override;

    // 获取 su/shell 进程 PID
    pid_t get_shell_pid() override;

    // shell 是否已经重新回到 prompt、可以继续输入下一条命令。
    // 后台任务仍在运行不影响结果。
    bool isShellForeground() const override;

private:
    static bool makePipe(int p[2]);
    static void setCloExec(int fd);
    static void safeClose(int& fd);
    static void setupShellPromptEnv_(std::string_view rc_dir);

    void readerLoop_();
    void consumeOutput_(const char* data, size_t size);
    void flushPendingOutput_();

private:
    pid_t m_pid{-1};

    int m_in_w{-1};     // parent -> child stdin (write end)
    int m_out_r{-1};    // child -> parent merged stdout/stderr (read end)

    mutable std::mutex m_mu;
    std::string m_out;

    // 只由 reader 线程访问；用于处理 marker 被 read() 拆开的情况。
    std::string m_parse_pending;

    std::atomic_bool m_shell_ready{false};
    std::thread m_reader;
};
