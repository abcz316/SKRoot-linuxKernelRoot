// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include "inventory.hpp"
extern "C" {
#include "../kernel/skp_sequential.h"
#include "../kernel/skp_full_objects.h"
}
#include <map>
#include <string>
#include <utility>
#include <vector>
namespace susfs::management {
// The standalone editor exposes one fixed default profile (#0) and at most seven
// user profiles.  The kernel ABI has a larger capacity, so this is a
// management/UI limit rather than a wire-format limit.
inline constexpr std::size_t kMaxProfiles = 8;
struct Subjects {
    bool blacklist=false,exempt_root=true,exempt_system_processes=true,exempt_system_apps=true;
    std::vector<std::string> whitelist_packages,blacklist_packages;
};
struct KstatRule { std::string path; skp_kstat_values values{}; };
struct RedirectRule { std::string source,target; std::string mode="path"; };
struct PathRule {
    std::string path;
    bool hide_contents=false;
    PathRule()=default;
    PathRule(const char* value):path(value){}
    PathRule(std::string value,bool contents=false):path(std::move(value)),hide_contents(contents){}
};
struct Rules {
    std::vector<PathRule> paths;
    std::vector<std::string> maps,mounts;
    std::vector<KstatRule> kstats;
    std::vector<RedirectRule> redirects;
    // Exact directory basenames share the sequential PATH family, but do not
    // resolve an inode and therefore remain distinct from absolute paths.
    std::vector<std::string> directory_names;
};
struct Profile {
    std::uint32_t id=0;
    std::string name;
    // Retained for schema10 profiles created before independent group policies.
    std::vector<std::string> packages;
    Rules rules;
    bool has_subjects=false;
    Subjects subjects{};
};
struct PathScope { std::uint32_t profile_id=0; std::string path; Subjects subjects; };
struct Config {
    bool upstream=true,object_rules_enabled=false;
    bool has_webui_settings=false,no_background=false;
    Subjects subjects;
    std::vector<Profile> profiles;
    std::vector<PathScope> path_scopes;
    // Set when an existing schema10 file contains more than kMaxProfiles.
    // Such a file is loaded and serialized intact for read-only inspection;
    // Service refuses to persist edits until the user reduces the count.
    bool profile_limit_exceeded=false;
    // Absent controls preserve upstream defaults, not a synthetic reset value.
    std::map<std::string,std::string> globals;
};
Config initial_config();
// Separate from the empty value factory: applied only on first installation.
bool initial_install_config(Config&,std::string& error);
bool parse_config(const std::string&,Config&,std::string& error);
std::string serialize_config(const Config&);
bool config_writable(const Config&,std::string& error);
bool compile_selector(const Config&,const Inventory&,const Profile&,
    const Subjects* path_override,skp_subject_policy&,std::uint32_t& profile_id,std::string& error);
}
