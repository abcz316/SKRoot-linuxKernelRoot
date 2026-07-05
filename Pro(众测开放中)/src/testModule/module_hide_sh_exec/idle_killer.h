#pragma once
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>

class IdleKiller {
public:
    // 返回 true：本次超时已经处理完，IdleKiller 线程结束
    // 返回 false：本次不杀，继续监控
    using OnTimeout = std::function<bool()>;

    void start(std::chrono::seconds timeout, OnTimeout cb);
    void touch();

private:
    std::atomic<bool>    m_started{false};
    std::atomic<int64_t> m_last_activity_ns{0};
    std::atomic<int64_t> m_timeout_ns{0};
    OnTimeout           m_on_timeout;
};