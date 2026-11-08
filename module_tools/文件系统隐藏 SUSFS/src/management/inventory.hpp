// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace susfs::management {
struct App { std::string package; std::uint32_t uid=0; bool system=false; };
struct Inventory { std::vector<App> apps; };
bool parse_inventory(const std::string& all,const std::string& system,Inventory&,std::string& error);
bool collect_inventory(Inventory&,std::string& error);
}
