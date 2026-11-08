// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <cJSON.h>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <string_view>
namespace susfs::management {
using Json=std::unique_ptr<cJSON,decltype(&cJSON_Delete)>;
Json parse_json(std::string_view,std::string& error,std::size_t limit=524288);
bool json_keys(const cJSON*,const std::set<std::string>&,bool exact=true);
const cJSON* member(const cJSON*,const char*);
bool decimal(std::string_view,std::uint64_t&);
bool signed_decimal(std::string_view,std::int64_t&);
bool json_string(const cJSON*,std::string&);
std::string quote(std::string_view);
bool valid_utf8(std::string_view);
bool package_name(std::string_view);
}
