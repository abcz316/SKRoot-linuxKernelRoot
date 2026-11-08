#include "../embedded.hpp"
#include "../config.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <unistd.h>
int main(){
    if(geteuid()!=0){std::cerr<<"root host fixture required\n";return 2;}
    // First launch must have its saved enabled preference before start() returns,
    // even while package facts/loader are unavailable on this non-Android host.
    char fresh[]="/tmp/susfs-default-lifecycle-XXXXXX";const char* made=mkdtemp(fresh);assert(made);
    const std::string first=made;std::string error;
    assert(susfs::embedded::start(first,error));
    assert(susfs::embedded::no_background(first));
    {std::ifstream stream(first+"/susfs/config.json");const std::string text((std::istreambuf_iterator<char>(stream)),{});
     susfs::management::Config decoded;assert(susfs::management::parse_config(text,decoded,error));
     assert(decoded.profiles.size()==2&&decoded.profiles[0].rules.paths.size()==2&&decoded.profiles[1].rules.paths.size()==1);
     for(const auto& profile:decoded.profiles)for(const auto& rule:profile.rules.paths)assert(rule.hide_contents);}
    assert(susfs::embedded::stop(first,error));std::filesystem::remove_all(first);
    char temp[]="/tmp/susfs-ui-lifecycle-XXXXXX";const char* p=mkdtemp(temp);assert(p);
    const std::string dir=p;std::filesystem::create_directory(dir+"/susfs");
    auto config=susfs::management::initial_config();config.has_webui_settings=true;config.no_background=true;
    {std::ofstream f(dir+"/susfs/config.json");f<<susfs::management::serialize_config(config);}
    assert(susfs::embedded::no_background(dir));
    assert(susfs::embedded::start(dir,error));
    auto result=susfs::embedded::request(dir,"/service/ping","");assert(result.status==200);
    result=susfs::embedded::request(dir,"/service/stop","{\"pid\":\"1\",\"stamp\":\"0\"}");
    assert(result.status==409); // wrong process generation must never stop the server
    assert(susfs::embedded::request(dir,"/service/ping","").status==200);
    assert(susfs::embedded::stop(dir,error));
    assert(!std::filesystem::exists(dir+"/susfs/control.sock"));
    assert(susfs::embedded::start(dir,error));
    result=susfs::embedded::request(dir,"/service/ping","");assert(result.status==200);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(25);
    while(std::filesystem::exists(dir+"/susfs/control.sock")&&std::chrono::steady_clock::now()<deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    assert(!std::filesystem::exists(dir+"/susfs/control.sock")); // no permanent boot daemon
    assert(susfs::embedded::stop(dir,error)); // idempotent cleanup after idle exit
    std::filesystem::remove_all(dir);
    std::cout<<"PASS embedded explicit stop, generation guard, restart and idle exit\n";
}
