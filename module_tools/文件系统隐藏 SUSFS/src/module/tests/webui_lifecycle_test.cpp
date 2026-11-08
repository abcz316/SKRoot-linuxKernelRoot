#include "../webui_lifecycle.h"
#include <cassert>
#include <thread>
#include <iostream>
int main(){
    susfs::WebuiLifecycle state(std::chrono::milliseconds(5));
    assert(!state.enabled()&&!state.closing()&&!state.expired());
    state.configure(true);assert(state.enabled()&&!state.expired());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));assert(state.expired());
    state.touch();assert(!state.expired());
    state.configure(false);std::this_thread::sleep_for(std::chrono::milliseconds(10));assert(!state.expired());
    std::thread worker([&]{for(unsigned i=0;i<10000;i++)state.touch();state.close();});
    for(unsigned i=0;i<10000;i++)(void)state.enabled();
    worker.join();assert(state.closing());
    state.configure(false);assert(state.closing()); // A closed page cannot rearm its old session.
    std::cout<<"PASS WebUI lifecycle\n";
}
