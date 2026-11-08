// SPDX-License-Identifier: GPL-2.0-only
#include "service.hpp"
#include "config_transfer.hpp"
#include "common.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace susfs::management {
namespace {
using Reply=susfs::embedded::Reply;
Reply error_reply(int status,const std::string& error,const char* result="not_executed"){
    return {status,"{\"ok\":false,\"saved\":false,\"result\":"+quote(result)+",\"error\":"+quote(error)+",\"steps\":[]}"};
}
const char* family_name(unsigned family){
    static const char* names[]={"global","path","kstat","map","redirect","mount"};
    return family<=5?names[family]:"unknown";
}
bool needs_inventory(const Config& config){
    if(config.upstream||!config.object_rules_enabled)return false;
    for(const auto& profile:config.profiles){
        const auto& r=profile.rules;
        if(!r.paths.empty()||!r.directory_names.empty()||!r.kstats.empty()||!r.maps.empty()||!r.redirects.empty()||!r.mounts.empty())return true;
    }
    return false;
}
std::string render_steps(const std::vector<Step>& steps){
    std::string s="[";bool first=true;
    for(const auto& x:steps){if(!first)s+=',';first=false;
        s+="{\"family\":"+quote(x.family)+",\"action\":"+quote(x.action)+",\"status\":"+quote(x.status)+
           ",\"profile_id\":"+std::to_string(x.profile_id)+",\"index\":"+std::to_string(x.index)+
           ",\"path\":"+quote(x.path)+",\"errno\":"+std::to_string(x.error_no)+",\"error\":"+quote(x.error)+
           (x.hide_contents?",\"hide_contents\":true":"")+"}";
    }return s+"]";
}
}
Service::Service(std::string dir,Backend& backend,InventoryReader inventory,ConfigWriter writer):
    directory_(std::move(dir)+"/susfs"),backend_(backend),inventory_(std::move(inventory)),writer_(std::move(writer)){}
bool Service::load(Config& c,std::string& error){
    std::string bytes;if(!read_file(directory_+"/config.json",bytes,error,524288))return false;
    return parse_config(bytes,c,error);
}
bool Service::save(const Config& c,std::string& error){
    // A legacy file may contain up to the kernel's profile capacity, but the
    // PLUS editor deliberately supports only eight.  Never persist a change
    // while that file is over the management limit; serialization itself
    // remains lossless so the UI can show and repair every profile.
    if(!config_writable(c,error))return false;
    if(writer_)return writer_(c,error);
    if(mkdir(directory_.c_str(),0700)&&errno!=EEXIST){error=std::strerror(errno);return false;}
    const auto target=directory_+"/config.json",temporary=target+".tmp";
    const int fd=open(temporary.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0){error=std::strerror(errno);return false;}
    const auto bytes=serialize_config(c);std::size_t offset=0;bool ok=true;
    while(offset<bytes.size()){
        const auto n=write(fd,bytes.data()+offset,bytes.size()-offset);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){ok=false;break;}offset+=static_cast<std::size_t>(n);
    }
    if(ok&&fsync(fd))ok=false;
    int code=errno;
    if(close(fd)&&ok){ok=false;code=errno;}
    if(ok&&rename(temporary.c_str(),target.c_str())){ok=false;code=errno;}
    if(!ok){unlink(temporary.c_str());error=std::strerror(code);return false;}
    no_background_.store(c.no_background);
    error.clear();return true;
}
bool Service::load_or_initialize(Config& config,std::string& error){
    struct stat st{};
    if(stat((directory_+"/config.json").c_str(),&st)){
        if(errno!=ENOENT){error=std::strerror(errno);return false;}
        if(!initial_install_config(config,error)||!save(config,error))return false;
    }else if(!load(config,error))return false;
    no_background_.store(config.no_background);
    error.clear();return true;
}
bool Service::prepare_configuration(std::string& error){
    Config config;return load_or_initialize(config,error);
}
bool Service::initialize(std::string& error){
    Config config;
    if(!load_or_initialize(config,error))return false;
    if(needs_inventory(config)){
        Inventory inventory;
        if(!inventory_(inventory,error)){
            if(error.empty())error="package_manager_unavailable";
            startup_apply_pending_=error=="package_manager_unavailable";
            defer_startup(config,error);error.clear();return true;
        }
        apply(config,true,&inventory);
    }else apply(config,true);
    return true;
}
Reply Service::defer_startup(const Config& config,const std::string& error){
    std::vector<Step> steps;
    auto append=[&](unsigned family,const char* action,unsigned profile,unsigned index,const std::string& path,bool directory_name=false,bool contents=false){
        steps.push_back({directory_name?"directory_name":family_name(family),action,"not_executed",error,path,profile,index,0,contents});
    };
    for(unsigned family=1;family<=5;++family)append(family,"clear",0,0,"");
    for(const auto& [key,value]:config.globals){(void)value;append(0,"set",0,0,key);}
    if(needs_inventory(config))for(const auto& profile:config.profiles){
        const auto& r=profile.rules;
        for(unsigned i=0;i<r.paths.size();++i)append(1,"add",profile.id,i,r.paths[i].path,false,r.paths[i].hide_contents);
        for(unsigned i=0;i<r.directory_names.size();++i)append(1,"add",profile.id,i,r.directory_names[i],true);
        for(unsigned i=0;i<r.kstats.size();++i)append(2,"add",profile.id,i,r.kstats[i].path);
        for(unsigned i=0;i<r.maps.size();++i)append(3,"add",profile.id,i,r.maps[i]);
        for(unsigned i=0;i<r.redirects.size();++i)append(4,"add",profile.id,i,r.redirects[i].source);
        for(unsigned i=0;i<r.mounts.size();++i)append(5,"add",profile.id,i,r.mounts[i]);
    }
    last_result_="{\"ok\":false,\"saved\":true,\"result\":\"not_executed\",\"error\":"+quote(error)+",\"steps\":"+render_steps(steps)+"}";
    return {200,last_result_};
}
bool Service::retry_startup_apply(){
    std::unique_lock<std::mutex> lock(mutex_,std::try_to_lock);
    if(!lock.owns_lock())return true;
    if(!startup_apply_pending_)return false;
    Config config;std::string error;
    if(!load(config,error)){
        startup_apply_pending_=false;last_result_=error_reply(500,error).body;return false;
    }
    if(!needs_inventory(config)){
        startup_apply_pending_=false;apply(config,true);return false;
    }
    // Package enumeration can wait on Android services. Keep status/config
    // requests available while probing, and recheck saved intent afterwards.
    lock.unlock();
    Inventory inventory;std::string inventory_error;
    const bool ready=inventory_(inventory,inventory_error);
    lock.lock();
    if(!startup_apply_pending_)return false;
    if(!load(config,error)){
        startup_apply_pending_=false;last_result_=error_reply(500,error).body;return false;
    }
    if(!needs_inventory(config)){
        startup_apply_pending_=false;apply(config,true);return false;
    }
    if(!ready){
        if(inventory_error.empty())inventory_error="package_manager_unavailable";
        startup_apply_pending_=inventory_error=="package_manager_unavailable";
        if(!startup_apply_pending_)defer_startup(config,inventory_error);
        return startup_apply_pending_;
    }
    startup_apply_pending_=false;
    apply(config,true,&inventory);return false;
}
Reply Service::apply(const Config& c,bool saved,const Inventory* prepared){
    no_background_.store(c.no_background);
    const bool was_startup_pending=startup_apply_pending_;
    startup_apply_pending_=false;
    std::vector<Step> steps;bool available=true;bool cleared[6]={};
    auto perform=[&](unsigned family,const std::string& action,unsigned profile,unsigned index,
                     const std::string& path,const std::function<Operation()>& action_fn,const std::string& skip="",bool directory_name=false,bool contents=false){
        Step step{directory_name?"directory_name":family_name(family),action,"not_executed","",path,profile,index,0,contents};
        if(!available)step.error="control_unavailable";
        else if(!skip.empty())step.error=skip;
        else{
            const auto op=action_fn();step.error_no=op.error_no;step.error=op.error;
            step.status=op.ok()?"applied":"failed";if(op.unavailable)available=false;
        }
        const bool ok=step.status=="applied";steps.push_back(std::move(step));return ok;
    };
    for(unsigned family=1;family<=5;++family)
        cleared[family]=perform(family,"clear",0,0,"",[&]{return backend_.clear(family);});
    for(const auto& [key,value]:c.globals)
        perform(0,"set",0,0,key,[&]{return backend_.global(key,value,c);});
    if(c.object_rules_enabled&&!c.upstream){
        Inventory inventory;std::string inventory_error;
        if(prepared)inventory=*prepared;
        else if(available&&needs_inventory(c)&&!inventory_(inventory,inventory_error)&&inventory_error.empty())inventory_error="package_manager_unavailable";
        startup_apply_pending_=was_startup_pending&&inventory_error=="package_manager_unavailable";
        for(const auto& profile:c.profiles){
            auto add=[&](unsigned family,unsigned index,const std::string& path,const std::string& target,const skp_kstat_values& values,bool content=false,bool directory_name=false,bool contents=false){
                std::string reason;skp_sequential_rule rule{};const Subjects* override=nullptr;
                if(!directory_name)for(const auto& scope:c.path_scopes)
                    if(scope.profile_id==profile.id&&scope.path==path){override=&scope.subjects;break;}
                if(!cleared[family])reason="family_clear_failed";
                else if(!inventory_error.empty())reason=inventory_error;
                else if(!compile_selector(c,inventory,profile,override,rule.subjects,rule.profile_id,reason)&&reason.empty())reason="group_resolution_failed";
                std::memcpy(rule.path,path.data(),path.size());std::memcpy(rule.target,target.data(),target.size());rule.values=values;
                perform(family,"add",profile.id,index,path,[&]{return contents?backend_.add_path_contents(rule):directory_name?backend_.add_directory_name(rule):content?backend_.add_content(rule):backend_.add(family,rule);},reason,directory_name,contents);
            };
            for(unsigned i=0;i<profile.rules.paths.size();++i){const auto& r=profile.rules.paths[i];add(1,i,r.path,"",{},false,false,r.hide_contents);}
            for(unsigned i=0;i<profile.rules.directory_names.size();++i)add(1,i,profile.rules.directory_names[i],"",{},false,true);
            for(unsigned i=0;i<profile.rules.kstats.size();++i){const auto& r=profile.rules.kstats[i];add(2,i,r.path,"",r.values);}
            for(unsigned i=0;i<profile.rules.maps.size();++i)add(3,i,profile.rules.maps[i],"",{});
            for(unsigned i=0;i<profile.rules.redirects.size();++i){const auto& r=profile.rules.redirects[i];add(4,i,r.source,r.target,{},r.mode=="content");}
            for(unsigned i=0;i<profile.rules.mounts.size();++i)add(5,i,profile.rules.mounts[i],"",{});
        }
    }
    bool all=true,any=false;for(const auto& step:steps){all&=step.status=="applied";any|=step.status=="applied";}
    const char* result=all?"applied":any?"partial":"not_executed";
    last_result_="{\"ok\":"+std::string(all?"true":"false")+",\"saved\":"+(saved?"true":"false")+
        ",\"result\":"+quote(result)+",\"steps\":"+render_steps(steps)+"}";
    return {200,last_result_};
}
Reply Service::handle(const std::string& route,const std::string& body){
    // Package enumeration does not read or mutate service configuration. It
    // may wait for Android, so it must not occupy the configuration/apply lock.
    if(route=="/apps"){
        Inventory inventory;std::string error;
        if(!inventory_(inventory,error))return error_reply(503,error);
        std::map<std::uint32_t,unsigned> counts;for(const auto& app:inventory.apps)++counts[app.uid];
        std::string response="{\"ok\":true,\"apps\":[";bool first=true;
        for(const auto& app:inventory.apps){if(!first)response+=',';first=false;
            response+="{\"package\":"+quote(app.package)+",\"uid\":"+std::to_string(app.uid)+
                ",\"is_system\":"+(app.system?"true":"false")+",\"shared_uid\":"+(counts[app.uid]>1?"true":"false")+"}";
        }return {200,response+"]}"};
    }
    std::unique_lock<std::mutex> lock(mutex_,std::try_to_lock);
    if(!lock.owns_lock())return error_reply(409,"busy");
    std::string error;
    if(route=="/status"){
        const auto raw=backend_.status();
        std::string capability_error,capabilities;
        const auto parsed=parse_json(raw,capability_error);
        if(parsed&&cJSON_IsObject(parsed.get())){
            for(const char* name:{"content_redirect","content_disabled_reason","content_sources","content_regular_files","content_regular_filesystems","content_max_bytes","content_limit_bytes","content_bytes","dirent","directory_name_hide","directory_name_match","directory_name_count","path_contents_hide","path_contents_disabled_reason","path_contents_mode"}){
                const auto* field=member(parsed.get(),name);if(!field)continue;
                char* value=cJSON_PrintUnformatted(field);if(value){capabilities+=","+quote(name)+":"+value;cJSON_free(value);}
            }
        }
        return {200,"{\"ok\":true,\"service_running\":true,\"kernel\":{\"online\":"+
            std::string(raw.empty()?"false":"true")+",\"raw\":"+quote(raw)+capabilities+"},\"loader_error\":"+quote(loader_error_)+",\"startup_apply_pending\":"+(startup_apply_pending_?"true":"false")+",\"last_result\":"+last_result_+"}"};
    }
    if(route=="/config"){
        Config config;if(!load(config,error))return error_reply(500,error);
        return {200,"{\"ok\":true,\"writable\":"+
            std::string(config.profile_limit_exceeded?"false":"true")+
            ",\"profile_limit_exceeded\":"+
            std::string(config.profile_limit_exceeded?"true":"false")+
            ",\"profile_count\":"+std::to_string(config.profiles.size())+
            ",\"max_profiles\":"+std::to_string(kMaxProfiles)+
            ",\"config\":"+serialize_config(config)+"}"};
    }
    if(route=="/config/import"||route=="/config/export"){
        auto input=parse_json(body,error);std::string path;
        if(!input||!json_string(member(input.get(),"path"),path))return error_reply(400,"path_required");
        Config current;if(!load(current,error))return error_reply(500,error);
        if(route=="/config/import"){
            Config imported;
            if(!import_config_file(path,imported,error))return error_reply(400,error);
            return {200,"{\"ok\":true,\"config\":"+serialize_config(imported)+"}"};
        }
        if(!export_config_file(path,current,error))return error_reply(400,error);
        return {200,"{\"ok\":true,\"path\":"+quote(path)+"}"};
    }
    if(route=="/config/save"){
        std::string text=body;
        auto envelope=parse_json(body,error);
        if(envelope&&member(envelope.get(),"config")){
            char* printed=cJSON_PrintUnformatted(member(envelope.get(),"config"));if(printed){text=printed;cJSON_free(printed);}
        }
        Config config;if(!parse_config(text,config,error)){auto reply=error_reply(400,error,"save_failed");last_result_=reply.body;return reply;}
        if(!config_writable(config,error)){
            auto reply=error_reply(400,error,"save_failed");last_result_=reply.body;return reply;
        }
        if(!save(config,error)){auto reply=error_reply(500,error,"save_failed");last_result_=reply.body;return reply;}
        auto result=apply(config,true);result.body.pop_back();result.body+=",\"config\":"+serialize_config(config)+"}";return result;
    }
    if(route=="/apply"){
        Config config;if(!load(config,error))return error_reply(500,error);
        return apply(config,true);
    }
    if(route=="/kstat/sample"){
        auto request=parse_json(body,error);std::string path;
        if(!request||!json_string(member(request.get(),"path"),path))return error_reply(400,"path_required");
        struct stat s{};if(stat(path.c_str(),&s))return error_reply(400,std::strerror(errno));
        std::string values="{\"ino\":"+quote(std::to_string(s.st_ino))+",\"dev_encoded\":"+quote(std::to_string((minor(s.st_dev)&0xffU)|(major(s.st_dev)<<8)|((minor(s.st_dev)&~0xffU)<<12)))+
          ",\"nlink\":"+quote(std::to_string(s.st_nlink))+",\"size\":"+quote(std::to_string(s.st_size))+
          ",\"atime_sec\":"+quote(std::to_string(s.st_atim.tv_sec))+",\"atime_nsec\":"+quote(std::to_string(s.st_atim.tv_nsec))+
          ",\"mtime_sec\":"+quote(std::to_string(s.st_mtim.tv_sec))+",\"mtime_nsec\":"+quote(std::to_string(s.st_mtim.tv_nsec))+
          ",\"ctime_sec\":"+quote(std::to_string(s.st_ctim.tv_sec))+",\"ctime_nsec\":"+quote(std::to_string(s.st_ctim.tv_nsec))+
          ",\"blocks\":"+quote(std::to_string(s.st_blocks))+",\"blksize\":"+quote(std::to_string(s.st_blksize))+"}";
        return {200,"{\"ok\":true,\"values\":"+values+"}"};
    }
    if(route=="/objects/query"){
        auto request=parse_json(body,error);const auto* paths=request?member(request.get(),"paths"):nullptr;
        if(!cJSON_IsArray(paths))return error_reply(400,"paths_required");
        Config config;if(!load(config,error))return error_reply(500,error);
        std::string result="{\"ok\":true,\"paths\":[";bool first_path=true;
        for(const auto* item=paths->child;item;item=item->next){
            std::string path;if(!json_string(item,path))return error_reply(400,"invalid_path");
            if(!first_path)result+=',';
            first_path=false;result+="{\"path\":"+quote(path)+",\"rules\":[";bool first_rule=true;
            auto add=[&](unsigned family,const Profile& profile,unsigned index,const std::string& candidate,bool contents=false){
                if(candidate!=path)return;
                if(!first_rule)result+=',';
                first_rule=false;
                result+="{\"kind\":"+quote(family_name(family))+",\"key\":"+quote(std::to_string(profile.id)+":"+std::to_string(family)+":"+std::to_string(index))+
                    ",\"profile_id\":"+std::to_string(profile.id)+",\"state\":\"unknown\""+(contents?",\"hide_contents\":true":"")+"}";
            };
            for(const auto& profile:config.profiles){
                for(unsigned i=0;i<profile.rules.paths.size();++i){const auto& r=profile.rules.paths[i];add(1,profile,i,r.path,r.hide_contents);}
                for(unsigned i=0;i<profile.rules.kstats.size();++i)add(2,profile,i,profile.rules.kstats[i].path);
                for(unsigned i=0;i<profile.rules.maps.size();++i)add(3,profile,i,profile.rules.maps[i]);
                for(unsigned i=0;i<profile.rules.redirects.size();++i)add(4,profile,i,profile.rules.redirects[i].source);
                for(unsigned i=0;i<profile.rules.mounts.size();++i)add(5,profile,i,profile.rules.mounts[i]);
            }result+="]}";
        }return {200,result+"]}"};
    }
    return error_reply(404,"unknown_route");
}
}
