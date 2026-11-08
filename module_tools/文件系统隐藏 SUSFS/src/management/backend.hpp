// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include "config.hpp"
#include <cerrno>
namespace susfs::management {
struct Operation { int error_no=0; std::string error; bool unavailable=false; bool ok()const{return error_no==0;} };
class Backend {
public:
    virtual ~Backend()=default;
    virtual Operation clear(unsigned family)=0;
    virtual Operation add(unsigned family,const skp_sequential_rule& rule)=0;
    virtual Operation add_content(const skp_sequential_rule&) { return {EOPNOTSUPP,"content_redirect_not_supported",false}; }
    virtual Operation add_directory_name(const skp_sequential_rule&) { return {EOPNOTSUPP,"directory_name_hide_not_supported",false}; }
    virtual Operation add_path_contents(const skp_sequential_rule&) { return {EOPNOTSUPP,"path_contents_hide_not_supported",false}; }
    virtual Operation global(const std::string& key,const std::string& value,const Config&)=0;
    virtual std::string status()=0;
};
class ProcBackend final:public Backend {
public:
    ~ProcBackend()override;
    Operation clear(unsigned) override;
    Operation add(unsigned,const skp_sequential_rule&) override;
    Operation add_content(const skp_sequential_rule&) override;
    Operation add_directory_name(const skp_sequential_rule&) override;
    Operation add_path_contents(const skp_sequential_rule&) override;
    Operation global(const std::string&,const std::string&,const Config&) override;
    std::string status() override;
private:
    int manager_fd_=-1;
    Operation manager();
};
bool read_file(const std::string& path,std::string&,std::string& error,std::size_t maximum=1048576);
}
