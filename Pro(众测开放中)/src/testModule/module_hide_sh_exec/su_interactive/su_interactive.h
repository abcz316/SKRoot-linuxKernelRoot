#pragma once
#include <sys/types.h>

#include <memory>
#include <string>
#include <string_view>

#include "isu_interactive.h"

// su 交互后端的实现方式
enum class SuInteractiveMode {
    Pty,    // PTY（伪终端）：提供 controlling tty，适合交互式脚本/程序
    Pipe,   // pipe：stderr 合并到 stdout，无 tty，实现简单
};

const char* su_interactive_mode_name(SuInteractiveMode mode);

SuInteractiveMode su_interactive_mode_from_name(std::string_view name);

std::unique_ptr<ISuInteractive> createSuInteractive(SuInteractiveMode mode);

class SuInteractive {
public:
    explicit SuInteractive(SuInteractiveMode mode = SuInteractiveMode::Pty);
    ~SuInteractive();

    DISABLE_COPY_MOVE(SuInteractive);

    // 启动 su
	// shell_rc_dir 非空时，会在该目录生成 .skroot_mkshrc，并设置 ENV/PS1/PS2/PROMPT。
    bool start(std::string_view shell_rc_dir = {});

    // 发送数据/发送一行（自动补 '\n'）
    bool send(const std::string& s);
    bool sendLine(const std::string& line);

    // 关闭输入（让对端收到 EOF）
    void closeInput();

    // 等待子进程退出（返回 exit code；信号：128+sig；失败 -1）
    int wait();

    // 停止并清理（语义同接口注释）
    void stop(bool force = true);

    // 获取累积输出（拷贝）
    std::string output() const;

    // 取走并清空累积输出
    std::string takeOutput();

    // 获取shell进程PID
    pid_t get_shell_pid();

    // 当前前台进程组是否已经回到 shell 自己（Pipe 模式恒 true）
    bool isShellForeground() const;

    // 当前使用的后端模式
    SuInteractiveMode mode() const;

private:
    SuInteractiveMode m_mode;
    std::unique_ptr<ISuInteractive> m_impl;
};
