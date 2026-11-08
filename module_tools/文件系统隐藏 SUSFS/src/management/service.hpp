// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include "backend.hpp"
#include "embedded.hpp"
#include <functional>
#include <mutex>
#include <atomic>
namespace susfs::management {
using InventoryReader=std::function<bool(Inventory&,std::string&)>;
using ConfigWriter=std::function<bool(const Config&,std::string&)>;
struct Step {
    std::string family,action,status,error,path;
    unsigned profile_id=0,index=0;int error_no=0;
    bool hide_contents=false;
};
class Service {
public:
    Service(std::string module_dir,Backend&,InventoryReader=collect_inventory,ConfigWriter={});
    // Establish saved first-install settings before publishing daemon readiness.
    // No package enumeration or kernel operations occur in this phase.
    bool prepare_configuration(std::string& error);
    bool initialize(std::string& error);
    // Returns true only while a startup restore still awaits package facts.
    bool retry_startup_apply();
    bool may_exit_idle() const { return no_background_.load()&&!startup_apply_pending_.load(); }
    susfs::embedded::Reply handle(const std::string& route,const std::string& body);
    void loader_error(std::string message){loader_error_=std::move(message);}
private:
    std::string directory_,last_result_="null",loader_error_;
    Backend& backend_;InventoryReader inventory_;ConfigWriter writer_;std::mutex mutex_;
    std::atomic<bool> startup_apply_pending_{false},no_background_{false};
    bool load(Config&,std::string&);
    bool load_or_initialize(Config&,std::string&);
    bool save(const Config&,std::string&);
    susfs::embedded::Reply defer_startup(const Config&,const std::string& error);
    susfs::embedded::Reply apply(const Config&,bool saved,const Inventory* prepared=nullptr);
};
}
