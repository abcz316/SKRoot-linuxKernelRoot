#pragma once
#include <sys/types.h>

#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "isu_interactive.h"

// PTY 版 su 交互：提供 controlling tty，适合交互脚本/程序
class PtySuInteractive : public ISuInteractive {
public:
    PtySuInteractive();
    ~PtySuInteractive() override;

    // 启动 su。提供 controlling tty。
    // shell_rc_dir 非空时，会在该目录生成 .skroot_mkshrc，并设置 ENV/PS1/PS2/PROMPT。
    bool start(std::string_view shell_rc_dir = {}) override;

    // 发送数据/发送一行（自动补 '\n'）
    bool send(const std::string& s) override;
    bool sendLine(const std::string& line) override;

    // 关闭输入（PTY 模式会关闭 master，让前台程序退出）
    void closeInput() override;

    // 等待子进程退出（返回 exit code；信号：128+sig；失败 -1）
    int wait() override;

    // 停止并清理：
    // force=false：不强杀，只关输入/输出fd并回收线程（对方若不退出可能 wait 会卡）
    // force=true ：SIGTERM + 短暂等待 + SIGKILL，确保回收
    void stop(bool force = true) override;

    // 获取累积输出（拷贝）
    std::string output() const override;

    // 取走并清空累积输出（更适合“增量取日志”）
    std::string takeOutput() override;

    // 获取shell进程PID
    pid_t get_shell_pid() override;

    // 当前 PTY 前台进程组是否已经回到 shell 自己
    bool isShellForeground() const override;
private:
    static void setCloExec(int fd);
    static void safeClose(int& fd);
    static void setupShellPromptEnv_(std::string_view rc_dir);

    bool startPty_(std::string_view shell_rc_dir);
    void readerLoop_();

private:
    pid_t m_pid{-1};

    int m_in_w{-1};     // PTY master 写端
    int m_out_r{-1};    // PTY master 读端（dup 出来的 fd）

    mutable std::mutex m_mu;
    std::string m_out;
    std::thread m_reader;
};
