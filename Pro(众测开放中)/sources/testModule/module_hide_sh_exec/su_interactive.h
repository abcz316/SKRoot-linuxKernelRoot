#pragma once
#include <sys/types.h>

#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

class SuInteractive {
public:
    SuInteractive();
    ~SuInteractive();

    SuInteractive(const SuInteractive&) = delete;
    SuInteractive& operator=(const SuInteractive&) = delete;

    // 启动 su；stderr 会合并到 stdout
    bool start();

    // 发送数据/发送一行（自动补 '\n'）
    bool send(const std::string& s);
    bool sendLine(const std::string& line);

    // 关闭输入（让对端收到 EOF）
    void closeInput();

    // 等待子进程退出（返回 exit code；信号：128+sig；失败 -1）
    int wait();

    // 停止并清理：
    // force=false：不强杀，只关输入/输出fd并回收线程（对方若不退出可能 wait 会卡）
    // force=true ：SIGTERM + 短暂等待 + SIGKILL，确保回收
    void stop(bool force = true);

    // 获取累积输出（拷贝）
    std::string output() const;

    // 取走并清空累积输出（更适合“增量取日志”）
    std::string takeOutput();

    // 获取shell进程PID
    pid_t get_shell_pid();
private:
    static bool makePipe(int p[2]);
    static void setCloExec(int fd);
    static void safeClose(int& fd);

    void readerLoop_();

private:
    pid_t m_pid{-1};

    int m_in_w{-1};     // parent -> child stdin (write end)
    int m_out_r{-1};    // child -> parent merged stdout/stderr (read end)

    mutable std::mutex m_mu;
    std::string m_out;
    std::thread m_reader;
};
