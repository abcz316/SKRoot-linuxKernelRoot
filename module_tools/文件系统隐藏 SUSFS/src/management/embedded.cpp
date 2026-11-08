// SPDX-License-Identifier: GPL-2.0-only
#include "embedded.hpp"
#include "service.hpp"
#include "common.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
namespace susfs::embedded {
namespace {
constexpr std::size_t maximum=4U*1024U*1024U;
bool process_stamp(pid_t pid,std::string& stamp){
    std::string stat,error;
    if(!management::read_file("/proc/"+std::to_string(pid)+"/stat",stat,error,8192))return false;
    const auto comm_end=stat.rfind(") ");if(comm_end==std::string::npos)return false;
    std::istringstream fields(stat.substr(comm_end+2));
    for(unsigned field=3;field<=22;++field)if(!(fields>>stamp))return false;
    std::uint64_t ticks=0;return management::decimal(stamp,ticks);
}
bool write_pid(const std::string& dir){
    std::string stamp;if(!process_stamp(getpid(),stamp))return false;
    const auto record=std::to_string(getpid())+" "+stamp+"\n";
    const int fd=open((dir+"/susfs/service.pid").c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
    if(fd<0)return false;
    const auto n=write(fd,record.data(),record.size());close(fd);
    return n==static_cast<ssize_t>(record.size());
}
bool transfer(int fd,void* data,std::size_t size,bool sending){
    auto* bytes=static_cast<char*>(data);std::size_t offset=0;
    while(offset<size){
        const auto n=sending?send(fd,bytes+offset,size-offset,MSG_NOSIGNAL):recv(fd,bytes+offset,size-offset,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        offset+=static_cast<std::size_t>(n);
    }return true;
}
bool send_frame(int fd,const std::string& bytes){
    if(bytes.size()>maximum)return false;
    std::uint32_t size=static_cast<std::uint32_t>(bytes.size());
    return transfer(fd,&size,sizeof(size),true)&&transfer(fd,const_cast<char*>(bytes.data()),bytes.size(),true);
}
bool receive_frame(int fd,std::string& bytes){
    std::uint32_t size=0;if(!transfer(fd,&size,sizeof(size),false)||size>maximum)return false;
    bytes.resize(size);return transfer(fd,bytes.data(),size,false);
}
bool address(const std::string& path,sockaddr_un& addr){
    if(path.size()>=sizeof(addr.sun_path))return false;
    addr={};addr.sun_family=AF_UNIX;std::memcpy(addr.sun_path,path.c_str(),path.size()+1);return true;
}
void timeouts(int fd,int seconds=120){
    timeval timeout{seconds,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
}
bool permitted(int fd){
    ucred peer{};socklen_t length=sizeof(peer);
    return getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length)==0&&peer.uid==0;
}
std::string load_module(const std::string& module_dir){
    const auto script=module_dir+"/lkm/load.sh";const pid_t child=fork();
    if(child<0)return std::strerror(errno);
    if(!child){
        const int output=open((module_dir+"/lkm/load.log").c_str(),O_WRONLY|O_CREAT|O_APPEND,0600);
        if(output>=0){dup2(output,1);dup2(output,2);close(output);}
        execl("/system/bin/sh","sh",script.c_str(),nullptr);_exit(127);
    }
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);
    int status=0;
    for(;;){
        const auto result=waitpid(child,&status,WNOHANG);
        if(result==child)return WIFEXITED(status)&&WEXITSTATUS(status)==0?"":"loader_exit_"+std::to_string(WIFEXITED(status)?WEXITSTATUS(status):-1);
        if(result<0&&errno!=EINTR)return std::strerror(errno);
        if(std::chrono::steady_clock::now()>=deadline){kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}return "loader_timeout";}
        usleep(50000);
    }
}
void serve(int server,int ready,const std::string& module_dir){
    management::ProcBackend backend;management::Service service(module_dir,backend);
    // The WebUI reads its lifetime preference immediately after start(). Seed
    // first-install settings before readiness, independently of loader/PM time.
    // Keep a damaged existing file intact and let initialize report its error.
    std::string configuration_error;
    (void)service.prepare_configuration(configuration_error);
    // The listener is ready before loading, but requests are accepted only
    // after startup restore. Readiness is independent of kernel availability.
    if(!write_pid(module_dir)){close(ready);return;}
    const char success=1;
    if(write(ready,&success,1)!=1){close(ready);return;}
    close(ready);
    std::string error=load_module(module_dir);service.loader_error(error);
    if(!service.initialize(error))service.loader_error("restore: "+error);
    // Android's package service may not exist during the SDK boot callback.
    // Retry that startup dependency without blocking the control listener.
    std::mutex retry_mutex;std::condition_variable retry_wake;bool stopping=false;
    std::thread startup_retry([&]{
        std::unique_lock<std::mutex> lock(retry_mutex);
        while(!retry_wake.wait_for(lock,std::chrono::seconds(2),[&]{return stopping;})){
            lock.unlock();const bool pending=service.retry_startup_apply();lock.lock();
            if(!pending)break;
        }
    });
    std::atomic<unsigned> active{0};
    std::atomic<bool> closing{false};
    const auto now=[] {return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();};
    std::atomic<std::int64_t> last_activity{now()};
    std::mutex clients_mutex;std::condition_variable clients_finished;
    for(;;){
        if(closing.load())break;
        if(active.load()==0&&service.may_exit_idle()&&now()-last_activity.load()>20000)break;
        pollfd ready_client{server,POLLIN,0};
        const int polled=poll(&ready_client,1,200);
        if(polled<0){if(errno==EINTR)continue;break;}
        if(!polled)continue;
        if(!(ready_client.revents&POLLIN))break;
        const int client=accept4(server,nullptr,nullptr,SOCK_CLOEXEC);
        if(client<0){if(errno==EINTR)continue;break;}
        if(closing.load()||!permitted(client)||active.load()>=8){close(client);continue;}
        ++active;last_activity.store(now());timeouts(client);
        std::thread([client,server,&service,&active,&closing,&last_activity,&now,&clients_mutex,&clients_finished]{
            std::string bytes,error;
            if(receive_frame(client,bytes)){
                auto request=management::parse_json(bytes,error,maximum);std::string route,body;
                if(request&&management::json_string(management::member(request.get(),"route"),route)&&
                   management::json_string(management::member(request.get(),"body"),body)){
                    Reply reply;
                    if(route=="/service/ping")reply={200,"{\"ok\":true}"};
                    else if(route=="/service/stop"){
                        auto identity=management::parse_json(body,error);std::string pid,stamp,actual;
                        std::uint64_t number=0;
                        if(identity&&management::json_string(management::member(identity.get(),"pid"),pid)&&
                           management::decimal(pid,number)&&number==static_cast<std::uint64_t>(getpid())&&
                           management::json_string(management::member(identity.get(),"stamp"),stamp)&&
                           process_stamp(getpid(),actual)&&stamp==actual){
                            reply={200,"{\"ok\":true}"};
                            closing.store(true);
                            shutdown(server,SHUT_RDWR);
                        }else reply={409,"{\"ok\":false,\"error\":\"service_identity_mismatch\"}"};
                    }else reply=service.handle(route,body);
                    send_frame(client,"{\"status\":"+std::to_string(reply.status)+",\"body\":"+management::quote(reply.body)+"}");
                }
            }
            close(client);
            last_activity.store(now());
            {std::lock_guard<std::mutex> lock(clients_mutex);--active;clients_finished.notify_one();}
        }).detach();
    }
    {std::lock_guard<std::mutex> lock(retry_mutex);stopping=true;}
    retry_wake.notify_one();startup_retry.join();
    std::unique_lock<std::mutex> lock(clients_mutex);
    clients_finished.wait(lock,[&]{return active.load()==0;});
    unlink((module_dir+"/susfs/control.sock").c_str());
    unlink((module_dir+"/susfs/service.pid").c_str());
}
}
Reply request(const std::string& dir,const std::string& route,const std::string& body){
    auto failure=[](const char* reason){return Reply{503,"{\"ok\":false,\"error\":"+management::quote(reason)+",\"result\":\"not_executed\"}"};};
    sockaddr_un addr{};if(!address(dir+"/susfs/control.sock",addr))return failure("socket_path_too_long");
    const int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return failure("socket_failed");
    timeouts(fd,(route=="/service/stop"||route=="/service/ping")?2:120);
    if(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))||!permitted(fd)){close(fd);return failure("embedded_service_unavailable");}
    std::string envelope="{\"route\":"+management::quote(route)+",\"body\":"+management::quote(body)+"}",bytes,error;
    const bool ok=send_frame(fd,envelope)&&receive_frame(fd,bytes);close(fd);
    if(!ok)return failure("embedded_service_io_failed");
    auto parsed=management::parse_json(bytes,error,maximum);std::string response;
    const auto* status=parsed?management::member(parsed.get(),"status"):nullptr;
    if(!status||!cJSON_IsNumber(status)||!management::json_string(management::member(parsed.get(),"body"),response))return failure("embedded_service_reply_invalid");
    return {status->valueint,response};
}
bool start(const std::string& dir,std::string& error){
    error.clear();if(geteuid()!=0){error="root_required";return false;}
    const auto private_dir=dir+"/susfs";
    if(mkdir(private_dir.c_str(),0700)&&errno!=EEXIST){error=std::strerror(errno);return false;}
    const int lock=open((private_dir+"/service.lock").c_str(),O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(lock<0){error=std::strerror(errno);return false;}
    if(flock(lock,LOCK_EX|LOCK_NB)){
        const int code=errno;
        if(code!=EWOULDBLOCK){close(lock);error=std::strerror(code);return false;}
        // Opening a page renews the idle daemon before the first browser
        // heartbeat. A daemon that just exited releases this same lock.
        if(request(dir,"/service/ping","").status==200){close(lock);return true;}
        if(flock(lock,LOCK_EX|LOCK_NB)){close(lock);return true;}
    }
    sockaddr_un addr{};const auto path=private_dir+"/control.sock";
    if(!address(path,addr)){close(lock);error="socket_path_too_long";return false;}
    const int server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(server<0){error=std::strerror(errno);close(lock);return false;}
    unlink(path.c_str());
    if(bind(server,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))||chmod(path.c_str(),0600)||listen(server,8)){
        error=std::strerror(errno);close(server);close(lock);unlink(path.c_str());return false;
    }
    int ready[2];if(pipe2(ready,O_CLOEXEC)){error=std::strerror(errno);close(server);close(lock);unlink(path.c_str());return false;}
    const auto child=fork();
    if(child<0){error=std::strerror(errno);close(ready[0]);close(ready[1]);close(server);close(lock);unlink(path.c_str());return false;}
    if(!child){
        close(ready[0]);setsid();
        const int nullfd=open("/dev/null",O_RDWR);
        if(nullfd>=0){dup2(nullfd,0);dup2(nullfd,1);dup2(nullfd,2);}
        const long limit=sysconf(_SC_OPEN_MAX);
        for(int fd=3;fd<(limit>0?limit:65536);++fd)if(fd!=server&&fd!=lock&&fd!=ready[1])close(fd);
        serve(server,ready[1],dir);close(server);close(lock);_exit(0);
    }
    close(ready[1]);close(server);close(lock);char success=0;
    ssize_t count;do{count=read(ready[0],&success,1);}while(count<0&&errno==EINTR);
    close(ready[0]);
    if(count!=1||success!=1){error="embedded_service_start_failed";return false;}
    return true;
}
bool stop(const std::string& dir,std::string& error){
    error.clear();if(geteuid()!=0){error="root_required";return false;}
    const auto base=dir+"/susfs/";
    const int lock=open((base+"service.lock").c_str(),O_RDWR|O_CLOEXEC);
    if(lock<0){if(errno==ENOENT)return true;error=std::strerror(errno);return false;}
    auto clean=[&]{unlink((base+"service.pid").c_str());unlink((base+"control.sock").c_str());close(lock);};
    if(flock(lock,LOCK_EX|LOCK_NB)==0){clean();return true;}
    if(errno!=EWOULDBLOCK){error=std::strerror(errno);close(lock);return false;}
    std::string record,stamp,actual;std::uint64_t number=0;
    if(!management::read_file(base+"service.pid",record,error,128)){close(lock);return false;}
    std::istringstream input(record);std::string pid_text;
    if(!(input>>pid_text>>stamp)||!management::decimal(pid_text,number)||number<2||number>2147483647U||
       !process_stamp(static_cast<pid_t>(number),actual)||actual!=stamp){
        error="service_identity_mismatch";close(lock);return false;
    }
    // Ask this exact generation to drain requests before the existing pidfd
    // fallback. Do not send a stop request that could target a newer daemon.
    const auto graceful=request(dir,"/service/stop","{\"pid\":"+management::quote(pid_text)+",\"stamp\":"+management::quote(stamp)+"}");
    if(graceful.status==200){
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        do{
            if(flock(lock,LOCK_EX|LOCK_NB)==0){clean();return true;}
            usleep(10000);
        }while(std::chrono::steady_clock::now()<deadline);
    }
    // A pidfd holds this exact process across exit/PID reuse. An unsupported
    // kernel returns the real failure rather than signalling a guessed PID.
#if !defined(SYS_pidfd_open) && defined(__NR_pidfd_open)
#define SYS_pidfd_open __NR_pidfd_open
#endif
#if !defined(SYS_pidfd_send_signal) && defined(__NR_pidfd_send_signal)
#define SYS_pidfd_send_signal __NR_pidfd_send_signal
#endif
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    const int process=static_cast<int>(syscall(SYS_pidfd_open,static_cast<pid_t>(number),0));
    if(process<0){error=std::strerror(errno);close(lock);return false;}
    if(!process_stamp(static_cast<pid_t>(number),actual)||actual!=stamp){
        error="service_identity_mismatch";close(process);close(lock);return false;
    }
    if(syscall(SYS_pidfd_send_signal,process,SIGTERM,nullptr,0)){
        error=std::strerror(errno);close(process);close(lock);return false;
    }
    close(process);
#else
    error="pidfd_unavailable";close(lock);return false;
#endif
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do{
        if(flock(lock,LOCK_EX|LOCK_NB)==0){clean();return true;}
        usleep(10000);
    }while(std::chrono::steady_clock::now()<deadline);
    error="service_stop_timeout";close(lock);return false;
}
bool no_background(const std::string& dir){
    std::string data,error;management::Config config;
    return management::read_file(dir+"/susfs/config.json",data,error,524288)&&
        management::parse_config(data,config,error)&&config.no_background;
}
}
