#pragma once
#include "config.hpp"
namespace susfs::management {
bool import_config_file(const std::string& path,Config& imported,std::string& error);
bool export_config_file(const std::string& path,const Config& config,std::string& error);
}
