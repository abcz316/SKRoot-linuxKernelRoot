#include "idle_killer.h"

static int64_t now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}
static int64_t to_ns(std::chrono::seconds s) {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(s).count();
}

void IdleKiller::start(std::chrono::seconds timeout, OnTimeout cb) {
    m_timeout_ns = to_ns(timeout);
    m_on_timeout = std::move(cb);
    touch();
    bool expected = false;
    if (!m_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    std::thread([this] {
        for (;;) {
            const auto last = m_last_activity_ns.load(std::memory_order_acquire);
            const auto now  = now_ns();

            if (last != 0 && (now - last) > m_timeout_ns.load(std::memory_order_acquire)) {
                // 先取出回调再执行，避免回调里 _exit 导致奇怪竞态
                auto cb = m_on_timeout; // copy
                if (cb) cb();
                return;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }).detach();
}
void IdleKiller::touch() { m_last_activity_ns.store(now_ns(), std::memory_order_release); }
