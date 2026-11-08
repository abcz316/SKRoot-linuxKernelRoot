#pragma once
#include <atomic>
#include <chrono>
namespace susfs {
class WebuiLifecycle {
public:
    using Clock=std::chrono::steady_clock;
    explicit WebuiLifecycle(std::chrono::milliseconds timeout=std::chrono::seconds(20)):timeout_(timeout.count()){}
    void configure(bool enabled) { enabled_.store(enabled); touch(); }
    bool enabled()const{return enabled_.load();}
    bool closing()const{return closing_.load();}
    void touch(){last_.store(milliseconds());}
    bool expired()const{return enabled()&&milliseconds()-last_.load()>timeout_;}
    void close(){closing_.store(true);}
private:
    static long long milliseconds(){return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();}
    std::atomic<bool> enabled_{false},closing_{false};
    std::atomic<long long> last_{milliseconds()};
    const long long timeout_;
};
}
