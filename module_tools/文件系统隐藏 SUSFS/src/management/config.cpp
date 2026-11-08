// SPDX-License-Identifier: GPL-2.0-only
#include "config.hpp"
#include "default_config.hpp"
#include "common.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <tuple>

namespace susfs::management {
namespace {
constexpr std::size_t max_config_bytes=524288,max_packages=512;
constexpr std::size_t max_paths=8192;

constexpr const char* value_names[]={"ino","dev_encoded","nlink","size",
	"atime_sec","atime_nsec","mtime_sec","mtime_nsec","ctime_sec",
	"ctime_nsec","blocks","blksize"};

bool fail(std::string& error,const char* reason) {error=reason;return false;}
bool boolean(const cJSON* value,bool& output) {
	if(!cJSON_IsBool(value))return false;
	output=cJSON_IsTrue(value);return true;
}
bool numeric_id(const cJSON* value,std::uint32_t& output) {
	if(!cJSON_IsNumber(value)||!std::isfinite(value->valuedouble)||value->valuedouble<0||
	   value->valuedouble>=static_cast<double>(SKP_SUBJECT_NO_PROFILE)||
	   std::floor(value->valuedouble)!=value->valuedouble)return false;
	output=static_cast<std::uint32_t>(value->valuedouble);return true;
}
bool strings(const cJSON* value,std::vector<std::string>& output,std::size_t limit) {
	if(!cJSON_IsArray(value)||cJSON_GetArraySize(value)>static_cast<int>(limit))return false;
	for(auto* item=value->child;item;item=item->next) {
		std::string text;if(!json_string(item,text))return false;
		output.push_back(std::move(text));
	}
	return true;
}
bool parse_subjects(const cJSON* source,Subjects& subjects,std::string& error) {
	if(!json_keys(source,{"mode","exempt_root","exempt_system_processes","exempt_system_apps","whitelist_packages","blacklist_packages"}))return fail(error,"invalid_subject_fields");
	std::string mode;
	if(!json_string(member(source,"mode"),mode)||(mode!="whitelist"&&mode!="blacklist"))return fail(error,"invalid_subject_mode");
	subjects.blacklist=mode=="blacklist";
	if(!boolean(member(source,"exempt_root"),subjects.exempt_root)||
	   !boolean(member(source,"exempt_system_processes"),subjects.exempt_system_processes)||
	   !boolean(member(source,"exempt_system_apps"),subjects.exempt_system_apps))return fail(error,"invalid_subject_flag");
	if(!strings(member(source,"whitelist_packages"),subjects.whitelist_packages,SKP_SUBJECT_MAX_LIST_UIDS)||
	   !strings(member(source,"blacklist_packages"),subjects.blacklist_packages,SKP_SUBJECT_MAX_LIST_UIDS))return fail(error,"invalid_subject_packages");
	return true;
}
bool selected_value(const cJSON* value,unsigned bit,skp_kstat_values& output) {
	std::string text;if(!json_string(value,text))return false;
	std::uint64_t number=0;std::int64_t signed_number=0;
	switch(bit) {
	case 0:if(!decimal(text,number))return false;output.ino=number;break;
	case 1:if(!decimal(text,number)||number>UINT32_MAX)return false;output.dev_encoded=number;break;
	case 2:if(!decimal(text,number)||number>UINT32_MAX)return false;output.nlink=static_cast<std::uint32_t>(number);break;
	case 3:if(!signed_decimal(text,signed_number)||signed_number<0)return false;output.size=signed_number;break;
	case 4:if(!signed_decimal(text,signed_number))return false;output.atime_sec=signed_number;break;
	case 5:if(!decimal(text,number)||number>=1000000000)return false;output.atime_nsec=static_cast<std::uint32_t>(number);break;
	case 6:if(!signed_decimal(text,signed_number))return false;output.mtime_sec=signed_number;break;
	case 7:if(!decimal(text,number)||number>=1000000000)return false;output.mtime_nsec=static_cast<std::uint32_t>(number);break;
	case 8:if(!signed_decimal(text,signed_number))return false;output.ctime_sec=signed_number;break;
	case 9:if(!decimal(text,number)||number>=1000000000)return false;output.ctime_nsec=static_cast<std::uint32_t>(number);break;
	case 10:if(!signed_decimal(text,signed_number)||signed_number<0)return false;output.blocks=signed_number;break;
	case 11:if(!signed_decimal(text,signed_number)||signed_number<1||signed_number>INT32_MAX)return false;output.blksize=signed_number;break;
	default:return false;
	}
	output.flags|=1U<<bit;return true;
}
std::string value_text(const skp_kstat_values& value,unsigned bit) {
	switch(bit) {
	case 0:return std::to_string(value.ino);
	case 1:return std::to_string(value.dev_encoded);
	case 2:return std::to_string(value.nlink);
	case 3:return std::to_string(value.size);
	case 4:return std::to_string(value.atime_sec);
	case 5:return std::to_string(value.atime_nsec);
	case 6:return std::to_string(value.mtime_sec);
	case 7:return std::to_string(value.mtime_nsec);
	case 8:return std::to_string(value.ctime_sec);
	case 9:return std::to_string(value.ctime_nsec);
	case 10:return std::to_string(value.blocks);
	case 11:return std::to_string(value.blksize);
	default:return {};
	}
}
bool parse_paths(const cJSON* source,std::vector<PathRule>& rules,bool contents_schema) {
	if(!cJSON_IsArray(source)||cJSON_GetArraySize(source)>static_cast<int>(max_paths))return false;
	for(auto* item=source->child;item;item=item->next){
		PathRule rule;
		if(cJSON_IsString(item)){
			if(!json_string(item,rule.path))return false;
		}else if(!contents_schema||!json_keys(item,{"path","hide_contents"})||
			!json_string(member(item,"path"),rule.path)||
			!boolean(member(item,"hide_contents"),rule.hide_contents))return false;
		rules.push_back(std::move(rule));
	}
	return true;
}
bool parse_rules(const cJSON* source,Rules& rules,std::string& error,bool content_schema,bool directory_name_schema,bool contents_schema) {
	const std::set<std::string> legacy_fields={"paths","kstats","maps","redirects","mounts"};
	auto fields=legacy_fields;if(directory_name_schema)fields.insert("directory_names");
	if(!json_keys(source,fields,!directory_name_schema))return fail(error,"invalid_rule_fields");
	if(!parse_paths(member(source,"paths"),rules.paths,contents_schema)||
	   !strings(member(source,"maps"),rules.maps,SKP_GROUP_MAPS_MAX)||
	   !strings(member(source,"mounts"),rules.mounts,SKP_GROUP_MOUNTS_MAX))return fail(error,"invalid_rule_array");
	if(directory_name_schema&&member(source,"directory_names")){
		if(!strings(member(source,"directory_names"),rules.directory_names,max_paths)||
		   rules.paths.size()+rules.directory_names.size()>max_paths)return fail(error,"invalid_directory_name_array");
		std::set<std::string> names;
		for(const auto& name:rules.directory_names)
			if(name.empty()||name.size()>255||name=="."||name==".."||
			   name.find('/')!=std::string::npos||name.find('\0')!=std::string::npos||
			   !names.insert(name).second)return fail(error,"invalid_directory_name");
	}
	const auto* kstats=member(source,"kstats");
	if(!cJSON_IsArray(kstats)||cJSON_GetArraySize(kstats)>static_cast<int>(SKP_GROUP_KSTATS_MAX))return fail(error,"invalid_kstat_array");
	const std::set<std::string> names(std::begin(value_names),std::end(value_names));
	for(auto* item=kstats->child;item;item=item->next) {
		KstatRule rule;
		if(!json_keys(item,{"path","values"})||!json_string(member(item,"path"),rule.path))return fail(error,"invalid_kstat_rule");
		const auto* values=member(item,"values");
		if(!json_keys(values,names,false)||!values->child)return fail(error,"invalid_kstat_values");
		for(unsigned bit=0;bit<12;++bit)if(const auto* value=member(values,value_names[bit]))
			if(!selected_value(value,bit,rule.values))return fail(error,"invalid_kstat_value");
		rules.kstats.push_back(std::move(rule));
	}
	const auto* redirects=member(source,"redirects");
	if(!cJSON_IsArray(redirects)||cJSON_GetArraySize(redirects)>static_cast<int>(SKP_GROUP_REDIRECTS_MAX))return fail(error,"invalid_redirect_array");
	for(auto* item=redirects->child;item;item=item->next) {
		RedirectRule rule;
		if(!json_keys(item,content_schema?std::set<std::string>{"source","target","mode"}:std::set<std::string>{"source","target"},false)||
           !json_string(member(item,"source"),rule.source)||!json_string(member(item,"target"),rule.target))return fail(error,"invalid_redirect_rule");
        if(const auto* mode=member(item,"mode"))
            if(!json_string(mode,rule.mode)||(rule.mode!="path"&&rule.mode!="content"))return fail(error,"invalid_redirect_mode");
        if(rule.mode=="content"&&(rule.source.empty()||rule.source[0]!='/'||rule.source=="/"||
            rule.target.empty()||rule.target[0]!='/'||rule.target=="/"))
            return fail(error,"invalid_content_path");
        rules.redirects.push_back(std::move(rule));
	}
	return true;
}

bool path_ok(const std::string& p) {return !p.empty()&&p.size()<SKP_GROUP_PATH_LEN;}
std::string strings_json(const std::vector<std::string>& v) {
 std::string s="[";for(const auto& x:v){if(s.size()>1)s+=',';s+=quote(x);}return s+']';
}
std::string paths_json(const std::vector<PathRule>& v) {
 std::string s="[";for(const auto& x:v){if(s.size()>1)s+=',';
  s+=x.hide_contents?"{\"path\":"+quote(x.path)+",\"hide_contents\":true}":quote(x.path);
 }return s+']';
}
std::string subjects_json(const Subjects& x) {
 return "{\"mode\":"+quote(x.blacklist?"blacklist":"whitelist")+",\"exempt_root\":"+(x.exempt_root?"true":"false")+
 ",\"exempt_system_processes\":"+(x.exempt_system_processes?"true":"false")+",\"exempt_system_apps\":"+(x.exempt_system_apps?"true":"false")+
 ",\"whitelist_packages\":"+strings_json(x.whitelist_packages)+",\"blacklist_packages\":"+strings_json(x.blacklist_packages)+"}";
}
std::string rules_json(const Rules& x,bool directory_name_schema) {
 std::string s="{\"paths\":"+paths_json(x.paths)+",\"kstats\":[";bool first=true;
 for(const auto& r:x.kstats){if(!first)s+=',';first=false;s+="{\"path\":"+quote(r.path)+",\"values\":{";bool f=true;
 for(unsigned bit=0;bit<12;++bit)if(r.values.flags&(1U<<bit)){if(!f)s+=',';f=false;s+=quote(value_names[bit])+":"+quote(value_text(r.values,bit));}
 s+="}}";}
 s+="],\"maps\":"+strings_json(x.maps)+",\"redirects\":[";first=true;
 for(const auto& r:x.redirects){if(!first)s+=',';first=false;s+="{\"source\":"+quote(r.source)+",\"target\":"+quote(r.target);if(r.mode!="path")s+=",\"mode\":"+quote(r.mode);s+='}';}
 s+="],\"mounts\":"+strings_json(x.mounts);
 if(directory_name_schema)s+=",\"directory_names\":"+strings_json(x.directory_names);
 return s+"}";
}
bool packages_ok(const std::vector<std::string>& x) {
 return std::all_of(x.begin(),x.end(),[](const std::string& s){return package_name(s);});
}
bool subjects_ok(const Subjects& s){return packages_ok(s.whitelist_packages)&&packages_ok(s.blacklist_packages);}
}
Config initial_config(){Config c;c.profiles.push_back({0,"默认",{}, {}});return c;}
bool initial_install_config(Config& config,std::string& error){
 return parse_config(kInitialInstallConfig,config,error)&&config_writable(config,error);
}
bool parse_config(const std::string& text,Config& output,std::string& error) {
 auto root=parse_json(text,error,max_config_bytes);if(!root)return false;
 const auto* schema=member(root.get(),"schema");
 if(!cJSON_IsNumber(schema)||(schema->valuedouble!=10&&schema->valuedouble!=11&&schema->valuedouble!=12&&schema->valuedouble!=13&&schema->valuedouble!=14))return fail(error,"unsupported_config_schema");
 const bool content_schema=schema->valuedouble>=11,directory_name_schema=schema->valuedouble>=12,contents_schema=schema->valuedouble>=14;
 if(!json_keys(root.get(),{"schema","mode","object_rules_enabled","subjects","profiles","path_scopes","globals","webui"},false))return fail(error,"invalid_config_fields");
 Config c;std::string mode;
 if(const auto* settings=member(root.get(),"webui")){
  if(schema->valuedouble<13||!json_keys(settings,{"no_background"})||
     !boolean(member(settings,"no_background"),c.no_background))return fail(error,"invalid_webui_settings");
  c.has_webui_settings=true;
 }
 if(!json_string(member(root.get(),"mode"),mode)||(mode!="upstream"&&mode!="groups"))return fail(error,"invalid_config_mode");
 c.upstream=mode=="upstream";
 if(!boolean(member(root.get(),"object_rules_enabled"),c.object_rules_enabled)||!parse_subjects(member(root.get(),"subjects"),c.subjects,error))return fail(error,"invalid_config_subjects");
 const auto* ps=member(root.get(),"profiles");
 if(!cJSON_IsArray(ps)||cJSON_GetArraySize(ps)>static_cast<int>(SKP_SUBJECT_MAX_PROFILES))return fail(error,"invalid_profiles");
 // Keep an over-limit legacy file readable and lossless.  The service marks
 // it read-only instead of truncating profiles or rejecting startup; the
 // caller must merge/delete profiles before saving a new configuration.
 c.profile_limit_exceeded=static_cast<std::size_t>(cJSON_GetArraySize(ps))>kMaxProfiles;
 std::set<std::uint32_t> ids;std::set<std::string> assigned;
 for(auto* item=ps->child;item;item=item->next) {
  Profile p;if(!json_keys(item,{"id","name","packages","rules","subjects"},false)||!numeric_id(member(item,"id"),p.id)||
  !json_string(member(item,"name"),p.name)||!strings(member(item,"packages"),p.packages,max_packages))return fail(error,"invalid_profile");
  if(!parse_rules(member(item,"rules"),p.rules,error,content_schema,directory_name_schema,contents_schema))return false;
  if(c.upstream&&!p.rules.directory_names.empty())return fail(error,"directory_name_hide_requires_groups");
  if(const auto* subjects=member(item,"subjects")){
   p.has_subjects=true;
   if(!parse_subjects(subjects,p.subjects,error)||!subjects_ok(p.subjects)||!p.packages.empty())return fail(error,"invalid_profile_subjects");
  }
  if(!ids.insert(p.id).second||p.name.empty()||p.name.size()>128||!packages_ok(p.packages)||(p.id==0&&!p.packages.empty()))return fail(error,"invalid_profile");
  for(const auto& name:p.packages)if(!assigned.insert(name).second)return fail(error,"package_profile_conflict");
  for(const auto& rule:p.rules.paths){
   if(!path_ok(rule.path))return fail(error,"path_exceeds_upstream_buffer");
   if(rule.hide_contents&&(rule.path.front()!='/'||rule.path.find('\0')!=std::string::npos))return fail(error,"invalid_path_contents_path");
   if(c.upstream&&rule.hide_contents)return fail(error,"path_contents_hide_requires_groups");
  }
  for(const auto* paths:{&p.rules.maps,&p.rules.mounts})for(const auto& path:*paths)if(!path_ok(path))return fail(error,"path_exceeds_upstream_buffer");
  for(const auto& r:p.rules.kstats)if(!path_ok(r.path))return fail(error,"path_exceeds_upstream_buffer");
  for(const auto& r:p.rules.redirects){
   if(!path_ok(r.source)||!path_ok(r.target))return fail(error,"path_exceeds_upstream_buffer");
   if(c.upstream&&r.mode=="content")return fail(error,"content_redirect_requires_groups");
  }
  c.profiles.push_back(std::move(p));
 }
 if(!ids.count(0)||!subjects_ok(c.subjects))return fail(error,"invalid_default_profile_or_subjects");
 const auto* scopes=member(root.get(),"path_scopes");
	if(!cJSON_IsArray(scopes)||cJSON_GetArraySize(scopes)>static_cast<int>(max_paths))return fail(error,"invalid_path_scopes");
 std::set<std::pair<std::uint32_t,std::string>> seen;
 for(auto* item=scopes->child;item;item=item->next){
  PathScope scope;if(!json_keys(item,{"profile_id","path","subjects"})||!numeric_id(member(item,"profile_id"),scope.profile_id)||
  !json_string(member(item,"path"),scope.path)||!parse_subjects(member(item,"subjects"),scope.subjects,error)||
  !path_ok(scope.path)||!subjects_ok(scope.subjects)||!seen.emplace(scope.profile_id,scope.path).second)return fail(error,"invalid_path_scope");
  const auto p=std::find_if(c.profiles.begin(),c.profiles.end(),[&](const Profile& x){return x.id==scope.profile_id;});
  bool referenced=p!=c.profiles.end()&&std::any_of(p->rules.paths.begin(),p->rules.paths.end(),[&](const PathRule& r){return r.path==scope.path;});
  if(p!=c.profiles.end()&&!referenced) {
   referenced=std::find(p->rules.maps.begin(),p->rules.maps.end(),scope.path)!=p->rules.maps.end()||
    std::find(p->rules.mounts.begin(),p->rules.mounts.end(),scope.path)!=p->rules.mounts.end();
   if(!referenced)for(const auto& rule:p->rules.kstats)if(rule.path==scope.path){referenced=true;break;}
   if(!referenced)for(const auto& rule:p->rules.redirects)if(rule.source==scope.path){referenced=true;break;}
  }
  if(!referenced)return fail(error,"path_scope_reference_missing");
  c.path_scopes.push_back(std::move(scope));
 }
 if(const auto* g=member(root.get(),"globals")){
  if(!cJSON_IsObject(g))return fail(error,"invalid_global_fields");
  for(auto* v=g->child;v;v=v->next){
   std::string x;if(cJSON_IsBool(v))x=cJSON_IsTrue(v)?"1":"0";else if(!json_string(v,x))return fail(error,"invalid_global_value");
   if(x.size()>8191)return fail(error,"invalid_global_value");
   c.globals.emplace(v->string,std::move(x));
  }
 }
 output=std::move(c);return true;
}
std::string serialize_config(const Config& c){
 bool content=false;for(const auto& p:c.profiles)for(const auto& r:p.rules.redirects)content|=r.mode=="content";
 bool directory_names=false;for(const auto& p:c.profiles)directory_names|=!p.rules.directory_names.empty();
 bool path_contents=false;for(const auto& p:c.profiles)for(const auto& r:p.rules.paths)path_contents|=r.hide_contents;
 std::string s="{\"schema\":"+std::string(path_contents?"14":c.has_webui_settings?"13":directory_names?"12":content?"11":"10")+",\"mode\":"+quote(c.upstream?"upstream":"groups")+",\"object_rules_enabled\":"+(c.object_rules_enabled?"true":"false")+
 ",\"subjects\":"+subjects_json(c.subjects)+",\"profiles\":[";bool first=true;
 for(const auto& p:c.profiles){if(!first)s+=',';first=false;s+="{\"id\":"+std::to_string(p.id)+",\"name\":"+quote(p.name)+",\"packages\":"+strings_json(p.packages)+",\"rules\":"+rules_json(p.rules,directory_names);
  if(p.has_subjects)s+=",\"subjects\":"+subjects_json(p.subjects);
  s+='}';}
 s+="],\"path_scopes\":[";first=true;
 for(const auto& x:c.path_scopes){if(!first)s+=',';first=false;s+="{\"profile_id\":"+std::to_string(x.profile_id)+",\"path\":"+quote(x.path)+",\"subjects\":"+subjects_json(x.subjects)+"}";}
 s+="],\"globals\":{";first=true;for(const auto& [key,value]:c.globals){if(!first)s+=',';first=false;s+=quote(key)+":"+quote(value);}s+='}';
 if(c.has_webui_settings)s+=",\"webui\":{\"no_background\":"+std::string(c.no_background?"true":"false")+"}";
 return s+"}\n";
}
bool config_writable(const Config& c,std::string& error){
    if(c.profile_limit_exceeded||c.profiles.size()>kMaxProfiles){
        error="profile_limit_exceeded";
        return false;
    }
    error.clear();
    return true;
}
bool compile_selector(const Config& config,const Inventory& inventory,const Profile& profile,const Subjects* override,
 skp_subject_policy& output,std::uint32_t& selected,std::string& error){
 output={};error.clear();output.version=SKP_SUBJECT_POLICY_VERSION;output.facts_generation=1;
 const auto& intent=override?*override:profile.has_subjects?profile.subjects:config.subjects;output.mode=intent.blacklist?SKP_SUBJECT_BLACKLIST:SKP_SUBJECT_WHITELIST;
 output.flags=(intent.exempt_root?SKP_SUBJECT_EXEMPT_ROOT:0)|(intent.exempt_system_processes?SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES:0)|(intent.exempt_system_apps?SKP_SUBJECT_EXEMPT_SYSTEM_APPS:0);
 std::map<std::string,const App*> apps;std::set<std::uint32_t> system,white,black;
 for(const auto& app:inventory.apps){apps[app.package]=&app;if(app.system)system.insert(app.uid);}
 auto resolve=[&](const std::vector<std::string>& names,std::set<std::uint32_t>& uids){
  for(const auto& name:names){const auto i=apps.find(name);if(i==apps.end()){error="package_not_found:"+name;return false;}
  if(i->second->uid>=SKP_SUBJECT_USER0_UID_LIMIT){error="unsupported_package_uid:"+name;return false;}uids.insert(i->second->uid);}return true;
 };
 // An explicit group retains both editor lists when switching modes, but
 // only its active list participates in the selector. Inactive uninstalled
 // packages must not prevent the visible policy from being applied. Keep
 // legacy group/path-scope resolution unchanged.
 if(profile.has_subjects&&!override){
  if(intent.blacklist?!resolve(intent.blacklist_packages,black):!resolve(intent.whitelist_packages,white))return false;
 }else if(!resolve(intent.whitelist_packages,white)||!resolve(intent.blacklist_packages,black))return false;
 if(white.size()>SKP_SUBJECT_MAX_LIST_UIDS||black.size()>SKP_SUBJECT_MAX_LIST_UIDS||system.size()>SKP_SUBJECT_MAX_SYSTEM_UIDS){error="subject_capacity";return false;}
 for(auto uid:white)output.whitelist[output.whitelist_count++]=uid;
 for(auto uid:black)output.blacklist[output.blacklist_count++]=uid;
 for(auto uid:system)output.system_apps[output.system_app_count++]=uid;
 // Every sequential rule carries its own selector. Explicit group policies
 // therefore use the same independent profile-zero projection as path scopes;
 // no shared UID-to-group binding can narrow another group's policy.
 if(override||profile.has_subjects){output.profiles[output.profile_count++]=0;selected=0;return true;}
 std::set<std::uint32_t> current;if(!resolve(profile.packages,current))return false;
 std::set<std::uint32_t> ids,conflicts;std::map<std::uint32_t,std::uint32_t> bindings;
 for(const auto& p:config.profiles){ids.insert(p.id);if(p.has_subjects)continue;for(const auto& name:p.packages){const auto a=apps.find(name);if(a==apps.end()||a->second->uid>=SKP_SUBJECT_USER0_UID_LIMIT)continue;
 const auto [i,inserted]=bindings.emplace(a->second->uid,p.id);if(!inserted&&i->second!=p.id)conflicts.insert(a->second->uid);}}
 for(auto uid:current)if(conflicts.count(uid)){error="shared_uid_profile_conflict";return false;}
 for(auto uid:conflicts)bindings.erase(uid);
 if(bindings.size()>SKP_SUBJECT_MAX_BINDINGS){error="binding_capacity";return false;}
 for(auto id:ids)output.profiles[output.profile_count++]=id;
 for(const auto& [uid,id]:bindings)output.bindings[output.binding_count++]={uid,id};
 selected=profile.id;return true;
}
}
