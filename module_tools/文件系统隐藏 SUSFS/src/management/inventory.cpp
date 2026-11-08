// SPDX-License-Identifier: GPL-2.0-only
#include "inventory.hpp"
#include "common.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
namespace susfs::management {
namespace {
bool command(bool system,std::string& output,std::string& error) {
    int fds[2];if(pipe2(fds,O_CLOEXEC)){error="package_pipe_failed";return false;}
    const pid_t child=fork();
    if(child<0){close(fds[0]);close(fds[1]);error="package_fork_failed";return false;}
    if(!child){
        dup2(fds[1],STDOUT_FILENO);
        const int nullfd=open("/dev/null",O_RDWR);if(nullfd>=0){dup2(nullfd,0);dup2(nullfd,2);}
#ifdef SYS_close_range
        if(syscall(SYS_close_range,3U,~0U,0U)!=0)
#endif
            for(int fd=3;fd<65536;++fd)close(fd);
        if(system)execl("/system/bin/cmd","cmd","package","list","packages","-U","-s","--user","0",nullptr);
        else execl("/system/bin/cmd","cmd","package","list","packages","-U","--user","0",nullptr);
        _exit(127);
    }
    close(fds[1]);fcntl(fds[0],F_SETFL,O_NONBLOCK);
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(15);
    bool ok=true,eof=false;output.clear();
    while(!eof&&std::chrono::steady_clock::now()<until){
        char bytes[8192];const auto n=read(fds[0],bytes,sizeof(bytes));
        if(n>0){output.append(bytes,static_cast<std::size_t>(n));if(output.size()>8U*1024U*1024U){ok=false;break;}}
        else if(n==0)eof=true;
        else if(errno!=EAGAIN&&errno!=EINTR){ok=false;break;}
        else {pollfd fd{fds[0],POLLIN|POLLHUP,0};poll(&fd,1,50);}
    }
    close(fds[0]);int status=0;
    if(!eof){ok=false;kill(child,SIGKILL);}
    for(;;){
        const auto waited=waitpid(child,&status,WNOHANG);
        if(waited==child)break;
        if(waited<0&&errno!=EINTR){ok=false;break;}
        if(std::chrono::steady_clock::now()>=until){ok=false;kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}break;}
        usleep(10000);
    }
    if(!ok||!WIFEXITED(status)||WEXITSTATUS(status)!=0){error="package_manager_unavailable";return false;}
    return true;
}
bool rows(const std::string& text,std::map<std::string,std::uint32_t>& output){
    std::istringstream in(text);std::string line;
    while(std::getline(in,line)){
        if(!line.empty()&&line.back()=='\r')line.pop_back();
        if(line.empty())continue;
        const auto split=line.find(" uid:");std::uint64_t uid=0;
        if(line.compare(0,8,"package:")||split==std::string::npos||
           !decimal(std::string_view(line).substr(split+5),uid)||uid>=UINT32_MAX)return false;
        const auto package=line.substr(8,split-8);if(!package_name(package))return false;
        output[package]=static_cast<std::uint32_t>(uid);
    }return true;
}
}
bool parse_inventory(const std::string& all,const std::string& system,Inventory& out,std::string& error){
    std::map<std::string,std::uint32_t> apps,systems;out={};error.clear();
    if(!rows(all,apps)||!rows(system,systems)){error="package_manager_output_invalid";return false;}
    for(const auto& [name,uid]:apps)out.apps.push_back({name,uid,systems.count(name)&&systems[name]==uid});
    return true;
}
bool collect_inventory(Inventory& out,std::string& error){
    std::string all,system;
    return command(false,all,error)&&command(true,system,error)&&parse_inventory(all,system,out,error);
}
}
