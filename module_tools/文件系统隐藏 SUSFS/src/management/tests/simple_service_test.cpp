// SPDX-License-Identifier: GPL-2.0-only
#include "../service.hpp"
#include "../common.hpp"
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <unistd.h>
using namespace susfs::management;
namespace {
struct FakeBackend:Backend{
    std::vector<std::string> calls;std::vector<skp_sequential_rule> rules;
    unsigned fail_clear=0,fail_add=0,disconnect_clear=0;
    bool content_supported=true,directory_name_supported=true,path_contents_supported=true;
    int path_contents_error=0;
    std::string status_text="sequential=1\n";
    std::mutex gate;std::condition_variable cv;bool blocking=false,entered=false,release=false;
    Operation clear(unsigned f)override{
        calls.push_back("clear:"+std::to_string(f));
        if(blocking){std::unique_lock<std::mutex> l(gate);entered=true;cv.notify_all();cv.wait(l,[&]{return release;});}
        if(f==disconnect_clear)return {ENODEV,"gone",true};
        return f==fail_clear?Operation{EIO,"clear failed",false}:Operation{};
    }
    Operation add(unsigned f,const skp_sequential_rule& r)override{
        calls.push_back("add:"+std::to_string(f)+":"+r.path);rules.push_back(r);
        return f==fail_add?Operation{EINVAL,"rule failed",false}:Operation{};
    }
    Operation add_content(const skp_sequential_rule& r)override{
        calls.push_back("content:4:"+std::string(r.path));
        if(!content_supported)return Backend::add_content(r);
        rules.push_back(r);return {};
    }
    Operation add_directory_name(const skp_sequential_rule& r)override{
        calls.push_back("directory_name:1:"+std::string(r.path));
        if(!directory_name_supported)return Backend::add_directory_name(r);
        rules.push_back(r);return {};
    }
    Operation add_path_contents(const skp_sequential_rule& r)override{
        calls.push_back("path_contents:1:"+std::string(r.path));
        if(!path_contents_supported)return Backend::add_path_contents(r);
        if(path_contents_error)return {path_contents_error,std::strerror(path_contents_error),false};
        rules.push_back(r);return {};
    }
    Operation global(const std::string& key,const std::string&,const Config&)override{calls.push_back("global:"+key);return {};}
    std::string status()override{return status_text;}
};
InventoryReader apps=[](Inventory& i,std::string&){i.apps={{"android",1000,true},{"test.probe",10242,false},{"test.shared",10242,false}};return true;};
Config example(){
    auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;c.subjects.blacklist=true;
    c.profiles[0].rules.paths={"/fixture/first","/fixture/second"};
    c.profiles[0].rules.maps={"/fixture/map"};c.globals["enable_log"]="0";return c;
}
std::string tempdir(){char path[]="/tmp/plus-service-test-XXXXXX";const auto* made=mkdtemp(path);assert(made);return made;}
Json parsed(const susfs::embedded::Reply& reply){std::string error;auto p=parse_json(reply.body,error);assert(p);return p;}
void expect_result(const susfs::embedded::Reply& reply,const char* expected){
    auto p=parsed(reply);assert(std::string(member(p.get(),"result")->valuestring)==expected);
}
std::string saved_config(const Config& config){
    const auto dir=tempdir();std::filesystem::create_directory(dir+"/susfs");
    std::ofstream stream(dir+"/susfs/config.json");stream<<serialize_config(config);stream.close();assert(stream);
    return dir;
}
void expect_pending(Service& service,bool expected){
    const auto reply=service.handle("/status","");assert(reply.status==200);
    const auto status=parsed(reply);const auto* pending=member(status.get(),"startup_apply_pending");
    assert(cJSON_IsBool(pending)&&bool(cJSON_IsTrue(pending))==expected);
}
}

static void transfer_and_preferences() {
    auto config=example();config.has_webui_settings=true;config.no_background=true;
    const auto dir=saved_config(config);FakeBackend backend;Service service(dir,backend,apps);
    std::string error;assert(service.initialize(error)&&service.may_exit_idle());
    Config decoded;assert(parse_config(serialize_config(config),decoded,error));
    assert(decoded.has_webui_settings&&decoded.no_background);
    backend.calls.clear();
    const auto target=dir+"/backup.json";
    auto reply=service.handle("/config/export","{\"path\":"+quote(target)+"}");
    assert(reply.status==200&&backend.calls.empty());
    std::string raw;assert(read_file(target,raw,error));auto wrapped=parse_json(raw,error);
    assert(wrapped&&std::string(member(wrapped.get(),"format")->valuestring)=="susfs4skp-config");
    const auto* exported=member(wrapped.get(),"config");
    assert(cJSON_IsTrue(member(member(exported,"webui"),"no_background")));
    assert(std::string(member(member(exported,"globals"),"enable_log")->valuestring)=="0");
    auto before=raw;
    reply=service.handle("/config/export","{\"path\":"+quote(target)+"}");
    assert(reply.status==400);assert(read_file(target,raw,error)&&raw==before);
    reply=service.handle("/config/import","{\"path\":"+quote(target)+"}");
    assert(reply.status==200&&backend.calls.empty());
    auto response=parsed(reply);assert(member(member(response.get(),"config"),"webui"));
    assert(cJSON_IsTrue(member(member(member(response.get(),"config"),"webui"),"no_background")));
    std::string saved;assert(read_file(dir+"/susfs/config.json",saved,error)&&saved==serialize_config(config));
    const auto bad=dir+"/bad.json";{std::ofstream stream(bad);stream<<"{invalid";}
    reply=service.handle("/config/import","{\"path\":"+quote(bad)+"}");assert(reply.status==400);
    {std::ofstream stream(bad);stream<<std::string(524289,'x');}
    reply=service.handle("/config/import","{\"path\":"+quote(bad)+"}");assert(reply.status==400);
    const auto link=dir+"/link.json";assert(!symlink(target.c_str(),link.c_str()));
    reply=service.handle("/config/import","{\"path\":"+quote(link)+"}");assert(reply.status==400);
    reply=service.handle("/config/import","{\"path\":\"relative.json\"}");assert(reply.status==400);
    config.no_background=false;reply=service.handle("/config/save",serialize_config(config));
    assert(reply.status==200&&!service.may_exit_idle());
    auto incoming=example();incoming.has_webui_settings=true;incoming.no_background=true;
    incoming.globals["release"]="6.6.fixture";
    {std::ofstream stream(bad);stream<<serialize_config(incoming);}
    reply=service.handle("/config/import","{\"path\":"+quote(bad)+"}");assert(reply.status==200);
    response=parsed(reply);assert(cJSON_IsTrue(member(member(member(response.get(),"config"),"webui"),"no_background")));
    assert(!service.may_exit_idle()); // Preview does not activate the imported lifetime setting.
    assert(std::string(member(member(member(response.get(),"config"),"globals"),"release")->valuestring)=="6.6.fixture");
    assert(read_file(dir+"/susfs/config.json",saved,error)&&saved==serialize_config(config));
    reply=service.handle("/config/save",serialize_config(incoming));assert(reply.status==200&&service.may_exit_idle());
    incoming.no_background=false;{std::ofstream stream(bad);stream<<serialize_config(incoming);}
    reply=service.handle("/config/import","{\"path\":"+quote(bad)+"}");assert(reply.status==200);
    response=parsed(reply);assert(cJSON_IsFalse(member(member(member(response.get(),"config"),"webui"),"no_background")));
    assert(service.may_exit_idle()); // False imports also remain drafts until saved.
    incoming.has_webui_settings=false;{std::ofstream stream(bad);stream<<serialize_config(incoming);}
    reply=service.handle("/config/import","{\"path\":"+quote(bad)+"}");assert(reply.status==200);
    response=parsed(reply);assert(!member(member(response.get(),"config"),"webui")); // Legacy files use the default off.
    assert(service.may_exit_idle());
    std::filesystem::remove_all(dir);
}

static void builtin_initial_configuration() {
    const std::vector<std::string> expected={"clear:1","clear:2","clear:3","clear:4","clear:5",
        "global:avc_spoof","global:enable_log","path_contents:1:/mnt/vendor/persist/data",
        "path_contents:1:/mnt/vendor/nvdata","path_contents:1:/data/adb"};
    std::string error;
    Config defaults;assert(initial_install_config(defaults,error));
    assert(!defaults.upstream&&defaults.object_rules_enabled&&defaults.has_webui_settings&&defaults.no_background);
    assert(defaults.profiles.size()==2&&defaults.profiles[0].id==0&&defaults.profiles[1].id==1);
    assert(defaults.profiles[0].name=="默认"&&defaults.profiles[1].name=="仅root");
    assert(defaults.profiles[0].rules.paths.size()==2&&defaults.profiles[0].rules.paths[0].path=="/mnt/vendor/persist/data"&&defaults.profiles[0].rules.paths[1].path=="/mnt/vendor/nvdata");
    assert(defaults.profiles[1].rules.paths.size()==1&&defaults.profiles[1].rules.paths[0].path=="/data/adb");
    for(const auto& p:defaults.profiles)for(const auto& r:p.rules.paths)assert(r.hide_contents);
    assert(serialize_config(defaults).find("\"schema\":14")!=std::string::npos);
    assert(defaults.profiles[0].has_subjects&&defaults.profiles[1].has_subjects);
    assert(!defaults.profiles[0].subjects.blacklist&&defaults.profiles[0].subjects.exempt_root&&
        defaults.profiles[0].subjects.exempt_system_processes&&!defaults.profiles[0].subjects.exempt_system_apps);
    assert(!defaults.profiles[1].subjects.blacklist&&defaults.profiles[1].subjects.exempt_root&&
        !defaults.profiles[1].subjects.exempt_system_processes&&!defaults.profiles[1].subjects.exempt_system_apps);
    assert((defaults.profiles[0].subjects.blacklist_packages==std::vector<std::string>{
        "bin.mt.plus","com.android.documentsui","com.coloros.filemanager"}));
    assert(defaults.globals.size()==2&&defaults.globals.at("avc_spoof")=="0"&&defaults.globals.at("enable_log")=="0");
    {
        // First-use preparation publishes settings before WebUI readiness,
        // without enumerating apps or touching the kernel. Initialization
        // later applies the seed through the normal five-family sequence.
        const auto fresh=tempdir();FakeBackend backend;unsigned reads=0;
        Service service(fresh,backend,[&](Inventory& inventory,std::string& e){++reads;return apps(inventory,e);});
        assert(service.prepare_configuration(error)&&error.empty());
        assert(reads==0&&backend.calls.empty()&&susfs::embedded::no_background(fresh));
        std::string persisted;assert(read_file(fresh+"/susfs/config.json",persisted,error));
        assert(persisted==serialize_config(defaults));
        assert(service.prepare_configuration(error)&&reads==0&&backend.calls.empty());
        assert(service.initialize(error)&&reads==1&&backend.calls==expected&&backend.rules.size()==3);
        assert(service.may_exit_idle());expect_pending(service,false);
        const auto status=parsed(service.handle("/status",""));
        assert(std::string(member(member(status.get(),"last_result"),"result")->valuestring)=="applied");
        const auto* initial_steps=member(member(status.get(),"last_result"),"steps");
        for(unsigned i=7;i<10;++i)assert(cJSON_IsTrue(member(cJSON_GetArrayItem(initial_steps,i),"hide_contents")));

        // User removal is ordinary saved intent, not an invitation to re-seed.
        auto cleared=defaults;cleared.profiles.resize(1);cleared.profiles[0].rules={};
        cleared.globals.clear();cleared.no_background=false;
        backend.calls.clear();backend.rules.clear();
        expect_result(service.handle("/config/save",serialize_config(cleared)),"applied");
        assert(reads==1&&backend.calls.size()==5&&backend.rules.empty()&&!service.may_exit_idle());
        assert(read_file(fresh+"/susfs/config.json",persisted,error)&&persisted==serialize_config(cleared));
        FakeBackend restored_backend;
        Service restored(fresh,restored_backend,[&](Inventory&,std::string&){assert(false);return false;});
        assert(restored.prepare_configuration(error)&&restored_backend.calls.empty());
        assert(restored.initialize(error)&&restored_backend.calls.size()==5&&restored_backend.rules.empty());
        assert(!restored.may_exit_idle()&&!susfs::embedded::no_background(fresh));
        assert(read_file(fresh+"/susfs/config.json",persisted,error)&&persisted==serialize_config(cleared));
        std::filesystem::remove_all(fresh);
    }
    {
        // Existing customized settings and rules are never merged with the
        // bundle, including an explicit preference to keep the service alive.
        auto customized=example();customized.has_webui_settings=true;customized.no_background=false;
        const auto dir=saved_config(customized);FakeBackend backend;Service service(dir,backend,apps);
        const auto before=serialize_config(customized);
        assert(service.prepare_configuration(error)&&backend.calls.empty());
        assert(service.initialize(error)&&backend.rules.size()==3&&!service.may_exit_idle());
        assert(std::string(backend.rules[0].path)=="/fixture/first");
        assert(backend.calls[6]=="add:1:/fixture/first"&&backend.calls[7]=="add:1:/fixture/second");
        std::string persisted;assert(read_file(dir+"/susfs/config.json",persisted,error)&&persisted==before);
        assert(!susfs::embedded::no_background(dir));
        std::filesystem::remove_all(dir);
    }
    {
        // Default-on background cleanup waits for first-boot package facts;
        // absence of the inactive-list apps must not block the later apply.
        const auto fresh=tempdir();FakeBackend backend;unsigned reads=0;bool ready=false;
        Service service(fresh,backend,[&](Inventory& inventory,std::string& e){
            ++reads;if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);
        });
        assert(service.prepare_configuration(error)&&reads==0&&backend.calls.empty());
        assert(service.initialize(error)&&error.empty()&&reads==1&&backend.calls.empty());
        expect_pending(service,true);assert(!service.may_exit_idle());
        assert(service.retry_startup_apply()&&reads==2&&backend.calls.empty()&&!service.may_exit_idle());
        ready=true;assert(!service.retry_startup_apply());expect_pending(service,false);
        assert(reads==3&&backend.calls==expected&&backend.rules.size()==3&&service.may_exit_idle());
        assert(!service.retry_startup_apply()&&reads==3&&backend.calls==expected);
        std::filesystem::remove_all(fresh);
    }
}

int main(){
    transfer_and_preferences();
    builtin_initial_configuration();
    const auto dir=tempdir();std::string error;
    {
        // A failed disk save cannot make any kernel call, including clearing.
        FakeBackend backend;Service s(dir,backend,apps,[](const Config&,std::string& e){e="disk full";return false;});
        auto r=s.handle("/config/save",serialize_config(example()));expect_result(r,"save_failed");assert(backend.calls.empty());
        assert(s.handle("/status","").body.find("save_failed")!=std::string::npos);
    }
    {
        // Ordered independent writes continue after one rejected family.
        FakeBackend backend;backend.fail_add=1;Service s(dir,backend,apps);
        auto r=s.handle("/config/save",serialize_config(example()));expect_result(r,"partial");
        const std::vector<std::string> expected={"clear:1","clear:2","clear:3","clear:4","clear:5","global:enable_log",
            "add:1:/fixture/first","add:1:/fixture/second","add:3:/fixture/map"};
        assert(backend.calls==expected);
        assert(s.handle("/config","").body.find("/fixture/second")!=std::string::npos);
        assert(!std::filesystem::exists(dir+"/susfs/config.json.tmp"));
        assert(serialize_config(example()).find("revision")==std::string::npos);
    }
    {
        FakeBackend backend;backend.fail_clear=1;Service s(dir,backend,apps);
        expect_result(s.handle("/config/save",serialize_config(example())),"partial");
        assert(backend.calls.size()==7&&backend.calls.back()=="add:3:/fixture/map");
        assert(s.handle("/status","").body.find("family_clear_failed")!=std::string::npos);
    }
    {
        // Losing the control device terminates calls, records the rest as unexecuted.
        FakeBackend backend;backend.disconnect_clear=2;bool inventoried=false;
        Service s(dir,backend,[&](Inventory&,std::string&){inventoried=true;return true;});
        auto r=s.handle("/config/save",serialize_config(example()));expect_result(r,"partial");
        assert((backend.calls==std::vector<std::string>{"clear:1","clear:2"}));assert(!inventoried);
        assert(r.body.find("not_executed")!=std::string::npos);
    }
    {
        // Restart replays saved intent from the beginning, with no task recovery state.
        FakeBackend backend;Service restarted(dir,backend,apps);assert(restarted.initialize(error));
        assert(backend.calls.size()==9&&backend.calls[0]=="clear:1"&&backend.calls.back()=="add:3:/fixture/map");
        assert(std::filesystem::directory_iterator(dir+"/susfs")!=std::filesystem::directory_iterator{});
    }
    {
        // A missing group's package only blocks that group's ordinary rules.
        auto c=example();c.profiles.push_back({7,"missing",{"not.installed"},{}});
        c.profiles.back().rules.paths={"/fixture/missing","/fixture/custom"};
        Subjects override;override.blacklist=true;c.path_scopes.push_back({7,"/fixture/custom",override});
        FakeBackend backend;Service s(dir,backend,apps);auto r=s.handle("/config/save",serialize_config(c));expect_result(r,"partial");
        assert(backend.calls.back()=="add:1:/fixture/custom");
        assert(backend.rules.back().profile_id==0&&backend.rules.back().subjects.binding_count==0);
        assert(r.body.find("package_not_found:not.installed")!=std::string::npos);
    }
    {
        // Full shared UIDs produce the same group, or an explicit local failure.
        auto c=example();c.profiles.push_back({2,"probe",{"test.probe"},{}});
        c.profiles.back().rules.paths={"/fixture/shared"};
        skp_subject_policy selector{};std::uint32_t profile=0;Inventory i;apps(i,error);
        assert(compile_selector(c,i,c.profiles.back(),nullptr,selector,profile,error));
        assert(profile==2&&selector.bindings[0].uid==10242);
        c.profiles.push_back({3,"shared",{"test.shared"},{}});
        assert(!compile_selector(c,i,c.profiles[1],nullptr,selector,profile,error));
        assert(error=="shared_uid_profile_conflict");
    }
    {
        // Explicit group policies are independent, may overlap, and use the
        // actual kernel evaluator for exclusion/specification decisions.
        auto c=example();
        Profile excluded;excluded.id=1;excluded.name="excluded";excluded.has_subjects=true;
        excluded.subjects.exempt_root=false;excluded.subjects.exempt_system_apps=false;
        excluded.subjects.whitelist_packages={"test.probe"};excluded.rules.paths={"/fixture/excluded"};
        Profile specified;specified.id=2;specified.name="specified";specified.has_subjects=true;
        specified.subjects.blacklist=true;specified.subjects.blacklist_packages={"test.probe"};
        specified.rules.paths={"/fixture/specified"};c.profiles.push_back(excluded);c.profiles.push_back(specified);
        Profile overlapping=specified;overlapping.id=3;overlapping.name="overlapping";
        overlapping.rules.paths={"/fixture/overlapping"};c.profiles.push_back(overlapping);
        Config decoded;assert(parse_config(serialize_config(c),decoded,error));
        assert(decoded.profiles[1].has_subjects&&!decoded.profiles[0].has_subjects);
        assert(serialize_config(decoded)==serialize_config(c));
        FakeBackend backend;Service s(dir,backend,apps);
        expect_result(s.handle("/config/save",serialize_config(c)),"applied");
        assert(backend.rules.size()==6);
        auto applies=[](const skp_sequential_rule& rule,std::uint32_t uid){
            assert(skp_subject_policy_validate(&rule.subjects)==SKP_SUBJECT_VALID);
            skp_subject_context context{};context.actual_uid=uid;
            const auto decision=skp_subject_evaluate(&rule.subjects,&context);
            return decision.applies&&decision.profile_id==rule.profile_id;
        };
        const auto& excluded_rule=backend.rules[3];
        const auto& specified_rule=backend.rules[4];
        const auto& overlapping_rule=backend.rules[5];
        assert(std::string(excluded_rule.path)=="/fixture/excluded");
        assert(excluded_rule.profile_id==0&&excluded_rule.subjects.binding_count==0);
        assert(applies(excluded_rule,0)&&!applies(excluded_rule,1000));
        assert(!applies(excluded_rule,10242)&&applies(excluded_rule,10300));
        assert(applies(specified_rule,10242)&&!applies(specified_rule,0)&&!applies(specified_rule,10300));
        assert(applies(overlapping_rule,10242));
        // A custom path scope keeps precedence over the group's policy.
        Subjects custom;custom.blacklist=true;custom.blacklist_packages={"android"};
        c.path_scopes.push_back({1,"/fixture/excluded",custom});
        backend.rules.clear();backend.calls.clear();
        expect_result(s.handle("/config/save",serialize_config(c)),"applied");
        assert(applies(backend.rules[3],1000)&&!applies(backend.rules[3],10300));
    }
    {
        // Hidden inactive lists survive mode switches without blocking an
        // explicit group's active selector when an old app is uninstalled.
        auto c=example();auto& group=c.profiles[0];group.has_subjects=true;
        group.subjects.blacklist=true;
        group.subjects.blacklist_packages={"test.probe"};
        group.subjects.whitelist_packages={"not.installed"};
        FakeBackend backend;Service s(dir,backend,apps);
        expect_result(s.handle("/config/save",serialize_config(c)),"applied");
        assert(backend.rules.size()==3);
        assert(backend.rules[0].subjects.blacklist_count==1&&backend.rules[0].subjects.whitelist_count==0);
        group.subjects.blacklist=false;
        group.subjects.whitelist_packages={"test.probe"};
        group.subjects.blacklist_packages={"not.installed"};
        backend.rules.clear();
        expect_result(s.handle("/config/save",serialize_config(c)),"applied");
        assert(backend.rules.size()==3);
        assert(backend.rules[0].subjects.whitelist_count==1&&backend.rules[0].subjects.blacklist_count==0);
        // A missing active package is still reported, never silently skipped.
        group.subjects.blacklist=true;backend.rules.clear();
        expect_result(s.handle("/config/save",serialize_config(c)),"partial");
        assert(backend.rules.empty());
        assert(s.handle("/status","").body.find("package_not_found:not.installed")!=std::string::npos);
        // Legacy group and custom path policies retain their old semantics.
        group.has_subjects=false;c.subjects=group.subjects;
        c.subjects.blacklist_packages={"test.probe"};c.subjects.whitelist_packages={"not.installed"};
        expect_result(s.handle("/config/save",serialize_config(c)),"partial");
        assert(backend.rules.empty());
        Inventory inventory;apps(inventory,error);skp_subject_policy selector{};std::uint32_t selected=0;
        group.has_subjects=true;
        assert(!compile_selector(c,inventory,group,&c.subjects,selector,selected,error));
        assert(error=="package_not_found:not.installed");
    }
    {
        // One active management call rejects another rather than enqueuing it.
        FakeBackend backend;backend.blocking=true;Service s(dir,backend,apps);
        std::thread t([&]{s.handle("/config/save",serialize_config(example()));});
        {std::unique_lock<std::mutex> l(backend.gate);backend.cv.wait(l,[&]{return backend.entered;});}
        assert(s.handle("/apply","").status==409);
        {std::lock_guard<std::mutex> l(backend.gate);backend.release=true;}backend.cv.notify_all();t.join();
    }
    {
        // App enumeration may wait on Android services, but must not make
        // the concurrently opened monitor or configuration report busy.
        const auto fresh=saved_config(initial_config());FakeBackend backend;
        std::mutex gate;std::condition_variable cv;bool entered=false,release=false;
        Service s(fresh,backend,[&](Inventory& inventory,std::string& e){
            std::unique_lock<std::mutex> lock(gate);entered=true;cv.notify_all();
            cv.wait(lock,[&]{return release;});return apps(inventory,e);
        });
        assert(s.initialize(error));const auto calls=backend.calls;
        susfs::embedded::Reply app_reply;
        std::thread enumeration([&]{app_reply=s.handle("/apps","");});
        {std::unique_lock<std::mutex> lock(gate);assert(cv.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}));}
        const auto started=std::chrono::steady_clock::now();
        const auto status_reply=s.handle("/status","");
        const auto config_reply=s.handle("/config","");
        const auto elapsed=std::chrono::steady_clock::now()-started;
        {std::lock_guard<std::mutex> lock(gate);release=true;}cv.notify_all();enumeration.join();
        assert(elapsed<std::chrono::seconds(1));
        assert(status_reply.status==200&&config_reply.status==200&&app_reply.status==200);
        const auto status_json=parsed(status_reply),config_json=parsed(config_reply),app_json=parsed(app_reply);
        assert(cJSON_IsTrue(member(status_json.get(),"service_running")));
        assert(cJSON_IsObject(member(config_json.get(),"config")));
        const auto* rows=member(app_json.get(),"apps");assert(cJSON_IsArray(rows)&&cJSON_GetArraySize(rows)==3);
        for(const auto* row=rows->child;row;row=row->next){
            const std::string package=member(row,"package")->valuestring;
            const bool system=package=="android";
            assert(member(row,"uid")->valueint==(system?1000:10242));
            assert(bool(cJSON_IsTrue(member(row,"is_system")))==system);
            assert(bool(cJSON_IsTrue(member(row,"shared_uid")))==!system);
        }
        assert(backend.calls==calls);std::filesystem::remove_all(fresh);
    }
    {
        // Existing empty intent remains empty, and a corrupt file is not silently reset.
        const auto fresh=saved_config(initial_config());FakeBackend backend;Service s(fresh,backend,apps);assert(s.initialize(error));
        assert(backend.calls.size()==5&&backend.rules.empty());
        std::ofstream(fresh+"/susfs/config.json")<<"{broken";
        backend.calls.clear();assert(!s.prepare_configuration(error)&&backend.calls.empty());
        assert(!s.initialize(error)&&backend.calls.empty());
        std::string invalid;assert(read_file(fresh+"/susfs/config.json",invalid,error)&&invalid=="{broken");
        std::filesystem::remove_all(fresh);
    }
    {
        // Legacy files with more than eight profiles remain readable and
        // lossless, but cannot be saved until the user removes/merges groups.
        auto over=example();
        for(unsigned id=1;id<=8;++id)over.profiles.push_back({id,"legacy-"+std::to_string(id),{}, {}});
        const auto encoded=serialize_config(over);
        Config parsed_config;assert(parse_config(encoded,parsed_config,error));
        assert(parsed_config.profile_limit_exceeded&&parsed_config.profiles.size()==9);
        assert(serialize_config(parsed_config)==encoded);
        std::string writable_error;assert(!config_writable(parsed_config,writable_error));
        assert(writable_error=="profile_limit_exceeded");

        const auto legacy=saved_config(initial_config());FakeBackend backend;Service s(legacy,backend,apps);
        assert(s.initialize(error));
        std::ofstream(legacy+"/susfs/config.json")<<encoded;
        backend.calls.clear();
        const auto read=s.handle("/config","");
        assert(read.body.find("\"writable\":false")!=std::string::npos);
        assert(read.body.find("\"profile_limit_exceeded\":true")!=std::string::npos);
        assert(read.body.find("\"profile_count\":9")!=std::string::npos);
        const auto rejected=s.handle("/config/save",encoded);
        expect_result(rejected,"save_failed");
        assert(rejected.body.find("profile_limit_exceeded")!=std::string::npos);
        assert(backend.calls.empty());
        std::ifstream persisted(legacy+"/susfs/config.json");
        const std::string after((std::istreambuf_iterator<char>(persisted)),{});
        assert(after==encoded);
        std::filesystem::remove_all(legacy);
    }
    {
        // Boot waits for package facts before any clear/global/add, and a
        // successful retry performs the ordinary sequence exactly once.
        auto config=example();skp_kstat_values values{};values.flags=1U<<3;values.size=17;
        config.profiles[0].rules.kstats.push_back({"/fixture/stat",values});
        config.profiles[0].rules.redirects.push_back({"/fixture/source","/fixture/target"});
        config.profiles[0].rules.mounts.push_back("/fixture/mount");
        const auto boot=saved_config(config);FakeBackend backend;unsigned reads=0;bool ready=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){
            ++reads;if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);
        });
        assert(s.initialize(error)&&error.empty());assert(reads==1&&backend.calls.empty());expect_pending(s,true);
        const auto status=parsed(s.handle("/status",""));const auto* result=member(status.get(),"last_result");
        assert(std::string(member(result,"result")->valuestring)=="not_executed");
        const auto* steps=member(result,"steps");assert(cJSON_GetArraySize(steps)==12);
        for(const auto* step=steps->child;step;step=step->next){
            assert(std::string(member(step,"status")->valuestring)=="not_executed");
            assert(std::string(member(step,"error")->valuestring)=="package_manager_unavailable");
        }
        assert(s.retry_startup_apply()&&s.retry_startup_apply());
        assert(reads==3&&backend.calls.empty());expect_pending(s,true);
        ready=true;assert(!s.retry_startup_apply());expect_pending(s,false);
        const std::vector<std::string> expected={"clear:1","clear:2","clear:3","clear:4","clear:5","global:enable_log",
            "add:1:/fixture/first","add:1:/fixture/second","add:2:/fixture/stat","add:3:/fixture/map",
            "add:4:/fixture/source","add:5:/fixture/mount"};
        assert(backend.calls==expected&&reads==4);
        assert(!s.retry_startup_apply()&&backend.calls==expected&&reads==4);
        std::filesystem::remove_all(boot);
    }
    {
        // A saved edit while Android is still starting replaces the intent
        // restored later; failed package lookup must keep recovery enabled.
        const auto boot=saved_config(example());FakeBackend backend;bool ready=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){
            if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);
        });
        assert(s.initialize(error));auto changed=example();
        changed.profiles[0].rules.paths={"/fixture/replacement"};changed.profiles[0].rules.maps.clear();
        expect_result(s.handle("/config/save",serialize_config(changed)),"partial");expect_pending(s,true);
        backend.calls.clear();backend.rules.clear();ready=true;
        assert(!s.retry_startup_apply());expect_pending(s,false);
        assert(backend.calls.size()==7&&backend.calls.back()=="add:1:/fixture/replacement");
        assert(backend.rules.size()==1&&std::string(backend.rules[0].path)=="/fixture/replacement");
        std::filesystem::remove_all(boot);
    }
    {
        // Rejected edits do not discard the valid saved startup intent.
        const auto boot=saved_config(example());FakeBackend backend;bool ready=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){
            if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);
        },[](const Config&,std::string& e){e="disk full";return false;});
        assert(s.initialize(error));expect_result(s.handle("/config/save","{broken"),"save_failed");
        expect_pending(s,true);expect_result(s.handle("/config/save",serialize_config(initial_config())),"save_failed");
        expect_pending(s,true);assert(backend.calls.empty());ready=true;
        assert(!s.retry_startup_apply());assert(backend.rules.size()==3);expect_pending(s,false);
        std::filesystem::remove_all(boot);
    }
    {
        // Invalid package output is a permanent diagnostic, whether observed
        // at startup or after a transient package-manager failure.
        for(bool initially_invalid:{false,true}){
            const auto boot=saved_config(example());FakeBackend backend;unsigned reads=0;
            Service s(boot,backend,[&](Inventory&,std::string& e){
                e=(++reads==1&&!initially_invalid)?"package_manager_unavailable":"package_manager_output_invalid";return false;
            });
            assert(s.initialize(error));expect_pending(s,!initially_invalid);
            assert(!s.retry_startup_apply());expect_pending(s,false);
            assert(s.handle("/status","").body.find("package_manager_output_invalid")!=std::string::npos);
            const auto stopped_reads=reads;assert(!s.retry_startup_apply());
            assert(reads==stopped_reads&&backend.calls.empty());std::filesystem::remove_all(boot);
        }
    }
    {
        // A saved file that becomes invalid is reported and is never silently
        // replaced or retried as the old configuration.
        const auto boot=saved_config(example());FakeBackend backend;unsigned reads=0;
        Service s(boot,backend,[&](Inventory&,std::string& e){++reads;e="package_manager_unavailable";return false;});
        assert(s.initialize(error));std::ofstream(boot+"/susfs/config.json")<<"{broken";
        assert(!s.retry_startup_apply());expect_pending(s,false);
        assert(reads==1&&backend.calls.empty());
        std::ofstream(boot+"/susfs/config.json")<<serialize_config(example());
        assert(!s.retry_startup_apply()&&reads==1&&backend.calls.empty());
        std::filesystem::remove_all(boot);
    }
    {
        // Once package facts are ready, selector/backend failures keep their
        // normal partial result and do not become an indefinite retry loop.
        for(bool missing_package:{false,true}){
            auto config=example();
            if(missing_package){config.profiles[0].has_subjects=true;config.profiles[0].subjects.blacklist=true;
                config.profiles[0].subjects.blacklist_packages={"not.installed"};}
            const auto boot=saved_config(config);FakeBackend backend;unsigned reads=0;
            if(!missing_package)backend.fail_add=1;
            Service s(boot,backend,[&](Inventory& inventory,std::string& e){
                if(++reads==1){e="package_manager_unavailable";return false;}return apps(inventory,e);
            });
            assert(s.initialize(error)&&!s.retry_startup_apply());expect_pending(s,false);
            const auto status=parsed(s.handle("/status",""));
            assert(std::string(member(member(status.get(),"last_result"),"result")->valuestring)=="partial");
            const auto calls=backend.calls;assert(!s.retry_startup_apply());assert(reads==2&&backend.calls==calls);
            std::filesystem::remove_all(boot);
        }
    }
    {
        // Configurations with no active object rules never depend on Android
        // package enumeration, even when their stored rules are nonempty.
        auto empty=example();empty.profiles[0].rules={};
        auto disabled=example();disabled.object_rules_enabled=false;
        auto upstream=example();upstream.upstream=true;
        for(const auto& config:{initial_config(),empty,disabled,upstream}){
            const auto boot=saved_config(config);FakeBackend backend;unsigned reads=0;
            Service s(boot,backend,[&](Inventory&,std::string& e){++reads;e="package_manager_unavailable";return false;});
            assert(s.initialize(error));expect_pending(s,false);assert(!s.retry_startup_apply());
            assert(reads==0&&backend.rules.empty());expect_result(s.handle("/apply",""),"applied");
            assert(reads==0&&backend.rules.empty());std::filesystem::remove_all(boot);
        }
    }
    {
        // A slow readiness probe leaves status/config readable. A concurrent
        // saved edit that is still pending must be reloaded after that probe.
        const auto boot=saved_config(example());FakeBackend backend;std::atomic<unsigned> reads{0};
        std::mutex gate;std::condition_variable cv;bool entered=false,release=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){
            const auto call=++reads;
            if(call==2){std::unique_lock<std::mutex> lock(gate);entered=true;cv.notify_all();
                cv.wait(lock,[&]{return release;});return apps(inventory,e);}
            assert(call==1||call==3);e="package_manager_unavailable";return false;
        });
        assert(s.initialize(error));bool pending=true;
        std::thread retry([&]{pending=s.retry_startup_apply();});
        {std::unique_lock<std::mutex> lock(gate);assert(cv.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}));}
        expect_pending(s,true);assert(s.handle("/config","").status==200);
        auto changed=example();changed.profiles[0].rules.paths={"/fixture/latest-during-probe"};changed.profiles[0].rules.maps.clear();
        expect_result(s.handle("/config/save",serialize_config(changed)),"partial");expect_pending(s,true);
        backend.calls.clear();backend.rules.clear();
        {std::lock_guard<std::mutex> lock(gate);release=true;}cv.notify_all();retry.join();
        assert(!pending&&reads==3);expect_pending(s,false);
        assert(backend.rules.size()==1&&std::string(backend.rules[0].path)=="/fixture/latest-during-probe");
        assert(backend.calls.size()==7&&backend.calls.back()=="add:1:/fixture/latest-during-probe");
        std::filesystem::remove_all(boot);
    }
    {
        // A successful user save while a readiness probe is in flight wins;
        // that stale probe must not clear or reapply the saved rules again.
        const auto boot=saved_config(example());FakeBackend backend;std::atomic<unsigned> reads{0};
        std::mutex gate;std::condition_variable cv;bool entered=false,release=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){
            const auto call=++reads;
            if(call==1){e="package_manager_unavailable";return false;}
            if(call==2){std::unique_lock<std::mutex> lock(gate);entered=true;cv.notify_all();cv.wait(lock,[&]{return release;});}
            return apps(inventory,e);
        });
        assert(s.initialize(error));bool pending=true;
        std::thread retry([&]{pending=s.retry_startup_apply();});
        {std::unique_lock<std::mutex> lock(gate);assert(cv.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}));}
        auto changed=example();changed.profiles[0].rules.paths={"/fixture/manual-wins"};changed.profiles[0].rules.maps.clear();
        expect_result(s.handle("/config/save",serialize_config(changed)),"applied");expect_pending(s,false);
        const auto calls=backend.calls;assert(calls.size()==7);
        {std::lock_guard<std::mutex> lock(gate);release=true;}cv.notify_all();retry.join();
        assert(!pending&&reads==3&&backend.calls==calls);assert(!s.retry_startup_apply()&&backend.calls==calls);
        assert(backend.rules.size()==1&&std::string(backend.rules[0].path)=="/fixture/manual-wins");
        std::filesystem::remove_all(boot);
    }
    {
        // New modes are explicit and cannot be erased by schema10 or old clients.
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        c.profiles[0].rules.redirects.push_back({"/proc/cpuinfo","/fixture/cpu.txt","content"});
        auto text=serialize_config(c);assert(text.find("\"schema\":11")!=std::string::npos);
        Config parsed_config;assert(parse_config(text,parsed_config,error));
        assert(parsed_config.profiles[0].rules.redirects[0].mode=="content");
        assert(serialize_config(parsed_config)==text);
        auto old=text;old.replace(old.find("\"schema\":11"),11,"\"schema\":10");
        assert(!parse_config(old,parsed_config,error)&&error=="invalid_redirect_rule");
        auto unknown=text;unknown.replace(unknown.find("\"content\""),9,"\"future\"");
        assert(!parse_config(unknown,parsed_config,error)&&error=="invalid_redirect_mode");
        // Configuration validates shape; the kernel owns the supported source types.
        for(const char* path:{"/proc/self/status","/fixtures/local-source","/proc/uptime"}){
            c.profiles[0].rules.redirects[0].source=path;
            assert(parse_config(serialize_config(c),parsed_config,error));
            assert(parsed_config.profiles[0].rules.redirects[0].source==path);
        }
        for(const char* path:{"relative","/"}){
            c.profiles[0].rules.redirects[0].source=path;
            assert(!parse_config(serialize_config(c),parsed_config,error)&&error=="invalid_content_path");
        }
        c.profiles[0].rules.redirects[0].source="/proc/cpuinfo";
        c.profiles[0].rules.redirects[0].target="relative";
        assert(!parse_config(serialize_config(c),parsed_config,error)&&error=="invalid_content_path");
        c.profiles[0].rules.redirects[0].target="/fixture/cpu.txt";
        c.profiles[0].rules.redirects[0].source="/proc/cpuinfo";c.upstream=true;
        assert(!parse_config(serialize_config(c),parsed_config,error)&&error=="content_redirect_requires_groups");
        for(const char* path:{"/proc/meminfo","/proc/version"}){
            c.upstream=false;c.profiles[0].rules.redirects[0].source=path;
            assert(parse_config(serialize_config(c),parsed_config,error));
        }
        c.profiles[0].rules.redirects[0].mode="path";
        text=serialize_config(c);assert(text.find("\"schema\":10")!=std::string::npos);
        assert(text.find("\"mode\":\"path\"")==std::string::npos);
        assert(parse_config(text,parsed_config,error)&&parsed_config.profiles[0].rules.redirects[0].mode=="path");
    }
    {
        // Content uses a dedicated operation, mixed with legacy path redirect.
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        c.profiles[0].rules.redirects={{"/proc/cpuinfo","/fixture/cpu.txt","content"},{"/fixture/source","/fixture/target"}};
        FakeBackend backend;Service s(dir,backend,apps);
        expect_result(s.handle("/config/save",serialize_config(c)),"applied");
        assert((backend.calls==std::vector<std::string>{"clear:1","clear:2","clear:3","clear:4","clear:5","content:4:/proc/cpuinfo","add:4:/fixture/source"}));
        assert(backend.rules.size()==2&&backend.rules[0].reserved==0);
        backend.calls.clear();backend.rules.clear();backend.content_supported=false;
        const auto reply=s.handle("/apply","");expect_result(reply,"partial");
        assert(reply.body.find("content_redirect_not_supported")!=std::string::npos);
        assert(backend.rules.size()==1&&std::string(backend.rules[0].path)=="/fixture/source");
    }
    {
        // Invalid upstream intent is rejected before changing saved configuration or kernel rules.
        auto c=initial_config();c.profiles[0].rules.redirects={{"/proc/cpuinfo","/fixture/cpu.txt","content"}};
        FakeBackend backend;Service s(dir,backend,apps);const auto reply=s.handle("/config/save",serialize_config(c));
        assert(reply.status==400&&backend.calls.empty());
        assert(reply.body.find("content_redirect_requires_groups")!=std::string::npos);
    }
    {
        // Exact names are a separate, explicit schema12 intent. Legacy
        // configurations remain byte-for-byte stable and cannot carry it.
        const auto legacy=serialize_config(initial_config());
        assert(legacy.find("directory_names")==std::string::npos);
        auto c=initial_config();c.upstream=false;c.profiles[0].rules.directory_names={"bin.mt.plus","中文目录",std::string(255,'a')};
        c.profiles.push_back({7,"other",{}, {}});
        auto text=serialize_config(c);Config decoded;
        assert(text.find("\"schema\":12")!=std::string::npos);
        assert(parse_config(text,decoded,error)&&serialize_config(decoded)==text);
        assert(decoded.profiles[0].rules.directory_names==c.profiles[0].rules.directory_names);
        assert(decoded.profiles[1].rules.directory_names.empty());
        auto absent=text;const auto empty_names=absent.find(",\"directory_names\":[]");assert(empty_names!=std::string::npos);
        absent.erase(empty_names,std::strlen(",\"directory_names\":[]"));
        assert(parse_config(absent,decoded,error)&&decoded.profiles[1].rules.directory_names.empty());
        for(const char* old_schema:{"10","11"}){
            auto old=text;old.replace(old.find("\"schema\":12"),11,std::string("\"schema\":")+old_schema);
            assert(!parse_config(old,decoded,error)&&error=="invalid_rule_fields");
        }
        for(const auto& name:std::vector<std::string>{"",".","..","parent/child",std::string(256,'a'),std::string("a\0b",3)}){
            c.profiles[0].rules.directory_names={name};
            assert(!parse_config(serialize_config(c),decoded,error));
        }
        c.profiles[0].rules.directory_names={"same","same"};
        assert(!parse_config(serialize_config(c),decoded,error)&&error=="invalid_directory_name");
        c.profiles[0].rules.directory_names={"same","Same","literal*name"};
        assert(parse_config(serialize_config(c),decoded,error));
        c.profiles[0].rules.directory_names={"bin.mt.plus"};c.upstream=true;
        assert(!parse_config(serialize_config(c),decoded,error)&&error=="directory_name_hide_requires_groups");
        c.upstream=false;c.profiles[0].rules.paths.assign(8192,"/fixture/p");
        assert(!parse_config(serialize_config(c),decoded,error)&&error=="invalid_directory_name_array");
        c.profiles[0].rules.paths.clear();c.profiles[0].rules.directory_names.clear();
        c.profiles[0].rules.redirects={{"/proc/cpuinfo","/fixture/cpu.txt","content"}};
        text=serialize_config(c);assert(text.find("\"schema\":11")!=std::string::npos&&text.find("directory_names")==std::string::npos);
        assert(parse_config(text,decoded,error)&&decoded.profiles[0].rules.directory_names.empty());
        c.profiles[0].rules.redirects.clear();c.profiles.pop_back();c.upstream=true;
        assert(serialize_config(c)==legacy);
    }
    {
        // Names use their dedicated command after the same five clears. The
        // independent group selector is retained; path overrides never apply.
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        auto& p=c.profiles[0];p.rules.paths={"bin.mt.plus"};p.rules.directory_names={"bin.mt.plus"};
        p.has_subjects=true;p.subjects.blacklist=true;p.subjects.blacklist_packages={"test.probe"};
        p.subjects.exempt_root=false;p.subjects.exempt_system_processes=false;p.subjects.exempt_system_apps=false;
        PathScope scope;scope.path="bin.mt.plus";scope.subjects.blacklist=false;scope.subjects.whitelist_packages={"test.probe"};c.path_scopes={scope};
        FakeBackend backend;Service s(dir,backend,apps);
        auto reply=s.handle("/config/save",serialize_config(c));expect_result(reply,"applied");
        assert((backend.calls==std::vector<std::string>{"clear:1","clear:2","clear:3","clear:4","clear:5","add:1:bin.mt.plus","directory_name:1:bin.mt.plus"}));
        assert(backend.rules.size()==2&&backend.rules[0].subjects.mode==SKP_SUBJECT_WHITELIST);
        const auto& rule=backend.rules[1];assert(rule.subjects.mode==SKP_SUBJECT_BLACKLIST&&rule.subjects.blacklist_count==1&&rule.subjects.blacklist[0]==10242);
        assert(rule.subjects.flags==0&&rule.profile_id==0&&rule.reserved==0&&rule.target[0]=='\0');
        const skp_kstat_values zero{};assert(std::memcmp(&rule.values,&zero,sizeof(zero))==0);
        auto body=parsed(reply);const auto* steps=member(body.get(),"steps");const auto* step=cJSON_GetArrayItem(steps,6);
        assert(std::string(member(step,"family")->valuestring)=="directory_name"&&std::string(member(step,"action")->valuestring)=="add");
        backend.calls.clear();backend.rules.clear();backend.directory_name_supported=false;
        reply=s.handle("/apply","");expect_result(reply,"partial");
        assert(reply.body.find("directory_name_hide_not_supported")!=std::string::npos);
        assert(backend.rules.size()==1&&backend.calls.back()=="directory_name:1:bin.mt.plus");
        backend.calls.clear();backend.rules.clear();backend.directory_name_supported=true;backend.fail_clear=1;
        reply=s.handle("/apply","");expect_result(reply,"partial");
        assert(backend.calls.size()==5&&backend.rules.empty());
        body=parsed(reply);steps=member(body.get(),"steps");step=cJSON_GetArrayItem(steps,6);
        assert(std::string(member(step,"family")->valuestring)=="directory_name"&&std::string(member(step,"error")->valuestring)=="family_clear_failed");
        c.upstream=true;backend.calls.clear();reply=s.handle("/config/save",serialize_config(c));
        assert(reply.status==400&&backend.calls.empty());
    }
    {
        // A name-only configuration still waits for Android package facts at
        // boot and reports the correct subtype while it is deferred.
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        c.profiles[0].rules.directory_names={"name-only"};
        const auto boot=saved_config(c);FakeBackend backend;bool ready=false;
        Service s(boot,backend,[&](Inventory& inventory,std::string& e){if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);});
        assert(s.initialize(error)&&backend.calls.empty());expect_pending(s,true);
        auto status_reply=parsed(s.handle("/status",""));const auto* steps=member(member(status_reply.get(),"last_result"),"steps");
        assert(cJSON_GetArraySize(steps)==6);
        const auto* step=cJSON_GetArrayItem(steps,5);assert(std::string(member(step,"family")->valuestring)=="directory_name");
        assert(std::string(member(step,"status")->valuestring)=="not_executed");
        ready=true;assert(!s.retry_startup_apply());expect_pending(s,false);
        assert(backend.calls.size()==6&&backend.calls.back()=="directory_name:1:name-only"&&backend.rules.size()==1);
        std::filesystem::remove_all(boot);
    }
    {
        // Folder contents are explicit schema14 intent. Existing string paths
        // retain whole-entry hiding and survive mixed imports/exports intact.
        const auto legacy=serialize_config(example());Config decoded;
        assert(parse_config(legacy,decoded,error)&&serialize_config(decoded)==legacy);
        for(const auto& r:decoded.profiles[0].rules.paths)assert(!r.hide_contents);
        auto c=example();c.has_webui_settings=true;c.no_background=true;
        c.profiles[0].rules.paths.emplace_back("/fixture/folder",true);
        PathScope scope;scope.path="/fixture/folder";scope.subjects.blacklist=true;
        scope.subjects.blacklist_packages={"test.probe"};c.path_scopes={scope};
        const auto text=serialize_config(c);assert(text.find("\"schema\":14")!=std::string::npos);
        assert(parse_config(text,decoded,error)&&serialize_config(decoded)==text);
        assert(decoded.no_background&&decoded.profiles[0].rules.paths[2].hide_contents);
        for(const char* version:{"10","11","12","13"}){
            auto old=text;old.replace(old.find("\"schema\":14"),11,std::string("\"schema\":")+version);
            assert(!parse_config(old,decoded,error));
        }
        auto invalid=text;invalid.replace(invalid.find("\"hide_contents\":true"),20,"\"hide_contents\":\"true\"");
        assert(!parse_config(invalid,decoded,error)&&error=="invalid_rule_array");
        invalid=text;invalid.insert(invalid.find("\"hide_contents\":true"),"\"extra\":0,");
        assert(!parse_config(invalid,decoded,error)&&error=="invalid_rule_array");
        invalid=text;invalid.replace(invalid.find("\"hide_contents\":true"),20,"\"hide_contents\":false");
        assert(parse_config(invalid,decoded,error)&&!decoded.profiles[0].rules.paths[2].hide_contents);
        c.profiles[0].rules.paths[2].path="relative";
        assert(!parse_config(serialize_config(c),decoded,error)&&error=="invalid_path_contents_path");
        c.profiles[0].rules.paths[2].path="/fixture/folder";c.upstream=true;
        assert(!parse_config(serialize_config(c),decoded,error)&&error=="path_contents_hide_requires_groups");
        c.upstream=false;const auto folder=saved_config(c);FakeBackend backend;Service s(folder,backend,apps);
        auto reply=s.handle("/config/export","{\"path\":"+quote(folder+"/contents.json")+"}");assert(reply.status==200);
        reply=s.handle("/config/import","{\"path\":"+quote(folder+"/contents.json")+"}");assert(reply.status==200&&backend.calls.empty());
        auto imported=parsed(reply);const auto* imported_paths=member(member(cJSON_GetArrayItem(member(member(imported.get(),"config"),"profiles"),0),"rules"),"paths");
        assert(cJSON_IsString(cJSON_GetArrayItem(imported_paths,0))&&cJSON_IsTrue(member(cJSON_GetArrayItem(imported_paths,2),"hide_contents")));
        std::filesystem::remove_all(folder);
    }
    {
        // Whole paths and contents use distinct commands with the same group
        // selectors and path overrides. Unsupported kernels never downgrade.
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        auto& p=c.profiles[0];p.rules.paths={"/fixture/whole",PathRule("/fixture/contents",true)};
        p.has_subjects=true;p.subjects.blacklist=true;p.subjects.blacklist_packages={"test.shared"};
        PathScope scope;scope.path="/fixture/contents";scope.subjects.blacklist=false;
        scope.subjects.whitelist_packages={"test.probe"};c.path_scopes={scope};
        FakeBackend backend;Service s(dir,backend,apps);
        auto reply=s.handle("/config/save",serialize_config(c));expect_result(reply,"applied");
        assert((backend.calls==std::vector<std::string>{"clear:1","clear:2","clear:3","clear:4","clear:5","add:1:/fixture/whole","path_contents:1:/fixture/contents"}));
        assert(backend.rules.size()==2&&backend.rules[0].subjects.mode==SKP_SUBJECT_BLACKLIST);
        const auto& applied=backend.rules[1];assert(applied.subjects.mode==SKP_SUBJECT_WHITELIST&&applied.subjects.whitelist_count==1&&applied.subjects.whitelist[0]==10242);
        assert(applied.reserved==0&&applied.target[0]=='\0');const skp_kstat_values zero{};assert(std::memcmp(&applied.values,&zero,sizeof(zero))==0);
        auto response=parsed(reply);const auto* step=cJSON_GetArrayItem(member(response.get(),"steps"),6);
        assert(std::string(member(step,"family")->valuestring)=="path"&&cJSON_IsTrue(member(step,"hide_contents")));
        response=parsed(s.handle("/objects/query","{\"paths\":[\"/fixture/contents\",\"/fixture/whole\"]}"));
        const auto* query=member(response.get(),"paths");const auto* entry=cJSON_GetArrayItem(member(cJSON_GetArrayItem(query,0),"rules"),0);
        assert(cJSON_IsTrue(member(entry,"hide_contents"))&&std::string(member(entry,"key")->valuestring)=="0:1:1");
        entry=cJSON_GetArrayItem(member(cJSON_GetArrayItem(query,1),"rules"),0);assert(!member(entry,"hide_contents"));
        backend.calls.clear();backend.rules.clear();backend.path_contents_supported=false;
        reply=s.handle("/apply","");expect_result(reply,"partial");assert(reply.body.find("path_contents_hide_not_supported")!=std::string::npos);
        assert(backend.rules.size()==1&&std::string(backend.rules[0].path)=="/fixture/whole");
        for(const int kernel_error:{EINVAL,ENOTDIR}){
            backend.calls.clear();backend.rules.clear();backend.path_contents_supported=true;backend.path_contents_error=kernel_error;
            reply=s.handle("/apply","");expect_result(reply,"partial");assert(backend.rules.size()==1);
            response=parsed(reply);step=cJSON_GetArrayItem(member(response.get(),"steps"),6);
            assert(member(step,"errno")->valueint==kernel_error&&std::string(member(step,"status")->valuestring)=="failed");
            assert(cJSON_IsTrue(member(step,"hide_contents"))&&backend.calls.back()=="path_contents:1:/fixture/contents");
        }
        backend.calls.clear();backend.rules.clear();backend.path_contents_supported=true;backend.fail_clear=1;
        reply=s.handle("/apply","");expect_result(reply,"partial");assert(backend.calls.size()==5&&backend.rules.empty());
    }
    {
        auto c=initial_config();c.upstream=false;c.object_rules_enabled=true;
        c.profiles[0].rules.paths.emplace_back("/fixture/deferred-folder",true);
        const auto folder=saved_config(c);FakeBackend backend;bool ready=false;
        Service s(folder,backend,[&](Inventory& inventory,std::string& e){if(!ready){e="package_manager_unavailable";return false;}return apps(inventory,e);});
        assert(s.initialize(error)&&backend.calls.empty());expect_pending(s,true);
        auto status=parsed(s.handle("/status",""));const auto* step=cJSON_GetArrayItem(member(member(status.get(),"last_result"),"steps"),5);
        assert(cJSON_IsTrue(member(step,"hide_contents"))&&std::string(member(step,"status")->valuestring)=="not_executed");
        ready=true;assert(!s.retry_startup_apply());expect_pending(s,false);
        assert(backend.calls.back()=="path_contents:1:/fixture/deferred-folder");std::filesystem::remove_all(folder);
    }
    {
        FakeBackend backend;backend.status_text="{\"directory_name_hide\":true,\"directory_name_match\":\"exact\",\"content_redirect\":true,\"content_sources\":[\"/proc/cpuinfo\"],\"content_regular_files\":true,\"content_regular_filesystems\":[\"ext4\",\"tmpfs\"],\"content_max_bytes\":1048576,\"content_limit_bytes\":8388608,\"content_bytes\":15,\"dirent\":{\"native\":true,\"compat\":false,\"filesystems\":[\"ext4\",\"f2fs\"],\"qualification_error\":0}}";
        Service s(dir,backend,apps);auto reply=parsed(s.handle("/status",""));const auto* kernel=member(reply.get(),"kernel");
        assert(cJSON_IsTrue(member(kernel,"content_redirect"))&&cJSON_IsArray(member(kernel,"content_sources")));
        assert(member(kernel,"content_bytes")->valueint==15);
        assert(cJSON_IsTrue(member(kernel,"content_regular_files"))&&cJSON_GetArraySize(member(kernel,"content_regular_filesystems"))==2);
        assert(cJSON_IsObject(member(kernel,"dirent"))&&cJSON_IsTrue(member(member(kernel,"dirent"),"native")));
        assert(cJSON_IsFalse(member(member(kernel,"dirent"),"compat")));
        assert(cJSON_IsTrue(member(kernel,"directory_name_hide"))&&std::string(member(kernel,"directory_name_match")->valuestring)=="exact");
        backend.status_text="{\"path_contents_hide\":false,\"path_contents_mode\":\"directory_search\",\"path_contents_disabled_reason\":\"directory_listing_unavailable\"}";
        reply=parsed(s.handle("/status",""));kernel=member(reply.get(),"kernel");
        assert(cJSON_IsFalse(member(kernel,"path_contents_hide")));
        assert(std::string(member(kernel,"path_contents_mode")->valuestring)=="directory_search");
        assert(std::string(member(kernel,"path_contents_disabled_reason")->valuestring)=="directory_listing_unavailable");
        backend.status_text="{\"content_redirect\":false,\"content_disabled_reason\":\"kernel_6_6_disabled\",\"directory_name_hide\":true}";
        reply=parsed(s.handle("/status",""));kernel=member(reply.get(),"kernel");
        assert(cJSON_IsFalse(member(kernel,"content_redirect"))&&cJSON_IsTrue(member(kernel,"directory_name_hide")));
        assert(std::string(member(kernel,"content_disabled_reason")->valuestring)=="kernel_6_6_disabled");
        backend.status_text="sequential=1\n";reply=parsed(s.handle("/status",""));kernel=member(reply.get(),"kernel");
        assert(!member(kernel,"content_redirect")&&!member(kernel,"content_regular_files")&&cJSON_IsTrue(member(kernel,"online")));
        assert(!member(kernel,"dirent"));
        assert(!member(kernel,"directory_name_hide")&&!member(kernel,"directory_name_match"));
        backend.status_text="{\"path_contents_hide\":true}";reply=parsed(s.handle("/status",""));
        assert(cJSON_IsTrue(member(member(reply.get(),"kernel"),"path_contents_hide")));
    }
    std::filesystem::remove_all(dir);
    std::cout<<"35 management scenarios passed: builtin seed/preparation/edit persistence, existing-config preservation, builtin startup recovery, save failure, sequential partial, clear failure, disconnect, restart, scoped group errors, UID semantics, independent group selectors, inactive mode lists, busy rejection, nonblocking app enumeration, empty/corrupt startup, over-limit legacy read-only, deferred startup recovery, latest saved intent, rejected-save recovery, permanent inventory errors, corrupt pending configuration, non-retrying rule failures, no-inventory configurations, responsive concurrent recovery, manual-save cancellation, explicit content schema validation, dedicated content apply and unsupported backend, upstream rejection, directory-name schema validation, directory-name selector and dedicated apply, name-only deferred boot, folder-contents schema/import/export validation, folder-contents selectors/query/dedicated apply/unsupported backend, folder-contents deferred startup, capability status compatibility\n";
}
