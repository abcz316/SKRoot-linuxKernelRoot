// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <string>
namespace susfs::embedded {
struct Reply {int status;std::string body;};
bool start(const std::string& module_dir,std::string& error);
bool stop(const std::string& module_dir,std::string& error);
Reply request(const std::string& module_dir,const std::string& route,const std::string& body);
bool no_background(const std::string& module_dir);
}
