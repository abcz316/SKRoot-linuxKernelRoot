#pragma once
#include <sys/types.h>

#include <string>
#include <string_view>

#include "kernel_module_kit_umbrella.h"

class ISuInteractive {
public:
    ISuInteractive() = default;
    virtual ~ISuInteractive() = default;

    DISABLE_COPY_MOVE(ISuInteractive);

    // 启动 su。
    // Pty 模式：shell_rc_dir 非空时会在该目录生成 .skroot_mkshrc 并设置提示符；
    // Pipe 模式：忽略 shell_rc_dir，stderr 合并到 stdout。
    virtual bool start(std::string_view shell_rc_dir = {}) = 0;

    // 发送数据/发送一行（自动补 '\n'）
    virtual bool send(const std::string& s) = 0;
    virtual bool sendLine(const std::string& line) = 0;

    // 关闭输入（让对端收到 EOF；PTY 模式会关闭 master）
    virtual void closeInput() = 0;

    // 等待子进程退出（返回 exit code；信号：128+sig；失败 -1）
    virtual int wait() = 0;

    // 停止并清理：
    // force=false：不强杀，只关输入/输出fd并回收线程（对方若不退出可能 wait 会卡）
    // force=true ：SIGTERM + 短暂等待 + SIGKILL，确保回收
    virtual void stop(bool force = true) = 0;

    // 获取累积输出（拷贝）
    virtual std::string output() const = 0;

    // 取走并清空累积输出（更适合“增量取日志”）
    virtual std::string takeOutput() = 0;

    // 获取shell进程PID
    virtual pid_t get_shell_pid() = 0;

    // 当前前台进程组是否已经回到 shell 自己。
    // Pipe 模式没有 controlling tty，无法判断，恒返回 true。
    virtual bool isShellForeground() const { return true; }
};
