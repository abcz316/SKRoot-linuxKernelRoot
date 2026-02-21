#pragma once
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>

class IdleKiller {
public:
    using OnTimeout = std::function<void()>;
    void start(std::chrono::seconds timeout, OnTimeout cb);
    void touch();
private:
    std::atomic<bool>   m_started{false};
    std::atomic<int64_t> m_last_activity_ns{0};
    std::atomic<int64_t> m_timeout_ns{0};
    OnTimeout            m_on_timeout;
};