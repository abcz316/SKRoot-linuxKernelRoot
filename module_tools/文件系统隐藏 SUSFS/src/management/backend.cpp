// SPDX-License-Identifier: GPL-2.0-only
#include "backend.hpp"
extern "C" {
#include "../kernel/susfs_abi.h"
}
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <sys/syscall.h>
#include <unistd.h>
namespace susfs::management {
namespace {
Operation failure(int code,bool unavailable=false){
    return {code,std::strerror(code),unavailable};
}
Operation write_node(const char* path,const void* bytes,std::size_t size,bool control){
    const int fd=open(path,O_WRONLY|O_CLOEXEC);
    if(fd<0)return failure(errno,control);
    const auto n=write(fd,bytes,size);const int code=errno;close(fd);
    if(n<0)return failure(code,control&&(code==ENODEV||code==EBADF||code==EPIPE));
    if(static_cast<std::size_t>(n)!=size)return failure(EIO,control);
    return {};
}
skp_sequential_header header(unsigned command,unsigned family,unsigned size){
    return {SKP_SEQUENTIAL_MAGIC,SKP_SEQUENTIAL_VERSION,size,command,family,0};
}
template<class T> Operation supercall(unsigned command,T& payload){
    payload.err=ERR_CMD_NOT_SUPPORTED;
    const auto rc=syscall(SYS_reboot,KSU_INSTALL_MAGIC1,SUSFS_MAGIC,command,&payload);
    const int code=errno;
    if(payload.err==ERR_CMD_NOT_SUPPORTED)return failure(rc<0?code:EOPNOTSUPP);
    if(payload.err)return failure(payload.err<0?-payload.err:payload.err);
    return {};
}
}
bool read_file(const std::string& path,std::string& bytes,std::string& error,std::size_t maximum){
    const int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC);bytes.clear();
    if(fd<0){error=std::strerror(errno);return false;}
    for(;;){
        char buffer[8192];const auto n=read(fd,buffer,sizeof(buffer));
        if(n<0&&errno==EINTR)continue;
        if(n<0){error=std::strerror(errno);close(fd);return false;}
        if(!n)break;
        if(bytes.size()+static_cast<std::size_t>(n)>maximum){error="file_too_large";close(fd);return false;}
        bytes.append(buffer,static_cast<std::size_t>(n));
    }
    close(fd);error.clear();return true;
}
Operation ProcBackend::manager(){
    if(manager_fd_>=0)return {};
    manager_fd_=open(SKP_SEQUENTIAL_NODE,O_WRONLY|O_CLOEXEC);
    if(manager_fd_<0)return failure(errno,true);
    auto h=header(SKP_SEQ_REGISTER_MANAGER,0,sizeof(skp_sequential_header));
    const auto n=write(manager_fd_,&h,sizeof(h));const int code=errno;
    if(n!=static_cast<ssize_t>(sizeof(h))){close(manager_fd_);manager_fd_=-1;return failure(n<0?code:EIO,true);}
    return {};
}
ProcBackend::~ProcBackend(){if(manager_fd_>=0)close(manager_fd_);}
Operation ProcBackend::clear(unsigned family){
    const auto ready=manager();if(!ready.ok())return ready;
    auto h=header(SKP_SEQ_CLEAR_FAMILY,family,sizeof(skp_sequential_header));
    return write_node(SKP_SEQUENTIAL_NODE,&h,sizeof(h),true);
}
Operation ProcBackend::add(unsigned family,const skp_sequential_rule& rule){
    skp_sequential_message m{};m.header=header(SKP_SEQ_ADD_RULE,family,sizeof(m));m.rule=rule;
    if(family==SKP_SEQ_PATH)m.header.flags=SKP_SEQ_ALLOW_PENDING;
    return write_node(SKP_SEQUENTIAL_NODE,&m,sizeof(m),true);
}
Operation ProcBackend::add_content(const skp_sequential_rule& rule){
    skp_sequential_message m{};m.header=header(SKP_SEQ_ADD_CONTENT,SKP_SEQ_REDIRECT,sizeof(m));m.rule=rule;
    const auto result=write_node(SKP_SEQUENTIAL_NODE,&m,sizeof(m),true);
    if(result.error_no==EINVAL||result.error_no==EOPNOTSUPP)return {result.error_no,"content_redirect_not_supported_or_invalid",result.unavailable};
    return result;
}
Operation ProcBackend::add_directory_name(const skp_sequential_rule& rule){
    skp_sequential_message m{};m.header=header(SKP_SEQ_ADD_DIR_NAME,SKP_SEQ_PATH,sizeof(m));m.rule=rule;
    const auto result=write_node(SKP_SEQUENTIAL_NODE,&m,sizeof(m),true);
    if(result.error_no==EINVAL||result.error_no==EOPNOTSUPP)return {result.error_no,"directory_name_hide_not_supported_or_invalid",result.unavailable};
    return result;
}
Operation ProcBackend::add_path_contents(const skp_sequential_rule& rule){
    skp_sequential_message m{};m.header=header(SKP_SEQ_ADD_PATH_CONTENTS,SKP_SEQ_PATH,sizeof(m));m.rule=rule;
    m.header.flags=SKP_SEQ_ALLOW_PENDING;
    const auto result=write_node(SKP_SEQUENTIAL_NODE,&m,sizeof(m),true);
    if(result.error_no==EOPNOTSUPP)return {result.error_no,"path_contents_hide_not_supported",result.unavailable};
    return result;
}
Operation ProcBackend::global(const std::string& key,const std::string& value,const Config& config){
    if(key=="cmdline"||key=="bootconfig"){
        if(value.size()>=SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)return failure(ENAMETOOLONG);
        st_susfs_spoof_cmdline_or_bootconfig p{};std::memcpy(p.fake_cmdline_or_bootconfig,value.data(),value.size());
        return supercall(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG,p);
    }
    if(key=="release"||key=="version"||(key=="uname_spoof_enabled"&&value!="0")){
        st_susfs_uname p{};
        auto field=[&](const char* name,char* target,std::size_t size)->bool{
            auto found=config.globals.find(name);std::string text=found==config.globals.end()?"default":found->second;
            if(text.size()>=size)return false;
            std::memcpy(target,text.data(),text.size());return true;
        };
        if(!field("release",p.release,sizeof(p.release))||!field("version",p.version,sizeof(p.version)))return failure(ENAMETOOLONG);
        return supercall(CMD_SUSFS_SET_UNAME,p);
    }
    static const std::map<std::string,std::string> paths={
        {"enable_log","/proc/susfs_enable_log"},{"avc_spoof","/proc/susfs_avc_spoof"},
        {"hide_modules","/proc/susfs_hide_modules"},
        {"uname_spoof_enabled","/sys/module/susfs_guard_lkm/parameters/uname_spoof_enabled"},
        {"hide_from_apps","/sys/module/susfs_guard_lkm/parameters/hide_from_apps"}
    };
    const auto found=paths.find(key);if(found==paths.end())return failure(EOPNOTSUPP);
    return write_node(found->second.c_str(),value.data(),value.size(),false);
}
std::string ProcBackend::status(){
    std::string bytes,error;if(!read_file(SKP_SEQUENTIAL_NODE,bytes,error))return {};
    return bytes;
}
}
