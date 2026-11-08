// SPDX-License-Identifier: GPL-2.0-only
#include "../../management/config.hpp"
#include "../../management/common.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

namespace m=susfs::management;
static unsigned checks=0;
#define CHECK(condition) do {++checks;if(!(condition)){std::fprintf(stderr,"management_config check %u line %d: %s\n",checks,__LINE__,#condition);std::exit(1);}} while(0)
static m::Config parsed(const std::string& text) {
	m::Config result;std::string error;CHECK(m::parse_config(text,result,error));CHECK(error.empty());return result;
}
static std::string replaced(std::string value,const std::string& before,const std::string& after) {
	const auto found=value.find(before);CHECK(found!=std::string::npos);value.replace(found,before.size(),after);return value;
}
static void rejected(const std::string& text) {
	auto output=m::initial_config();output.revision=71;
	const auto saved=m::serialize_config(output);std::string error;
	CHECK(!m::parse_config(text,output,error));CHECK(!error.empty());CHECK(m::serialize_config(output)==saved);
}
static void invalid(m::Config config) {
	std::string error;CHECK(!m::validate_config(config,error));CHECK(!error.empty());CHECK(m::serialize_config(config).empty());
}
static void refresh(m::Inventory& facts) {
	std::sort(facts.apps.begin(),facts.apps.end(),[](const m::App& a,const m::App& b){return a.package<b.package;});
	facts.fingerprint=m::inventory_fingerprint(facts);
}
static m::Inventory inventory() {
	m::Inventory facts;
	facts.apps={{"app.alpha",10001,false},{"app.shared",10001,true},{"app.beta",10002,false},{"app.gamma",10003,false}};
	facts.complete=true;facts.generation=77;facts.observed_ns=m::boottime_ns();
	refresh(facts);return facts;
}
static m::Config configured() {
	auto config=m::initial_config();config.revision=9007199254740993ULL;
	config.upstream=false;config.object_rules_enabled=true;
	config.subjects.whitelist_packages={"app.beta","app.uninstalled"};
	config.subjects.blacklist_packages={"app.alpha","app.uninstalled"};
	config.subjects.exempt_system_apps=false;
	config.profiles[0].rules.paths={"/owned/default"};
	m::Profile profile;profile.id=7;profile.name="中文 测试";
	profile.packages={"app.uninstalled","app.alpha"};
	profile.rules.paths={"/owned/中文 空格","/owned/z"};
	m::KstatRule stat;stat.path="/owned/stat";stat.values.flags=(1U<<0)|(1U<<1)|(1U<<3)|(1U<<8)|(1U<<9)|(1U<<11);
	stat.values.ino=UINT64_MAX;stat.values.dev_encoded=UINT32_MAX;stat.values.size=4096;
	stat.values.ctime_sec=INT64_MIN;stat.values.ctime_nsec=999999999;stat.values.blksize=4096;
	profile.rules.kstats.push_back(stat);profile.rules.maps={"/owned/maps"};
	profile.rules.redirects={{"/owned/source","/owned/target"}};profile.rules.mounts={"/owned/mount"};
	config.profiles.push_back(profile);return config;
}

static void parsing() {
	const auto initial=m::serialize_config(m::initial_config());CHECK(!initial.empty());
	auto config=parsed(initial);CHECK(config.revision==0&&config.upstream&&!config.object_rules_enabled);
	CHECK(config.profiles.size()==1&&config.profiles[0].id==0&&config.profiles[0].packages.empty());
	CHECK(m::serialize_config(config)==initial);
	auto full=configured();const auto encoded=m::serialize_config(full);CHECK(!encoded.empty());
	CHECK(encoded.find("9007199254740993")!=std::string::npos);
	CHECK(encoded.find("18446744073709551615")!=std::string::npos);
	CHECK(encoded.find("-9223372036854775808")!=std::string::npos);
	CHECK(m::serialize_config(parsed(encoded))==encoded);
	std::reverse(full.profiles.begin(),full.profiles.end());
	std::reverse(full.profiles[0].rules.paths.begin(),full.profiles[0].rules.paths.end());
	std::reverse(full.profiles[0].packages.begin(),full.profiles[0].packages.end());
	std::reverse(full.subjects.whitelist_packages.begin(),full.subjects.whitelist_packages.end());
	CHECK(m::serialize_config(full)==encoded);

	rejected("");rejected("null");rejected("{}");rejected(initial+"{}");
	rejected(replaced(initial,"\"schema\":10","\"schema\":8"));
	rejected(replaced(initial,"\"schema\":10","\"schema\":10,\"schema\":10"));
	rejected(replaced(initial,"\"schema\":10","\"schema\":10,\"uid\":10001"));
	rejected(replaced(initial,"\"revision\":\"0\"","\"revision\":0"));
	for(const auto* revision:{"18446744073709551616","-1","00","01","+1"," 1","1.0","","1e3"})
		rejected(replaced(initial,"\"revision\":\"0\"",std::string("\"revision\":\"")+revision+"\""));
	config=parsed(replaced(initial,"\"revision\":\"0\"","\"revision\":\"18446744073709551615\""));
	CHECK(config.revision==UINT64_MAX);
	rejected(replaced(initial,"\"mode\":\"upstream\"","\"mode\":\"wrong\""));
	rejected(replaced(initial,"\"object_rules_enabled\":false","\"object_rules_enabled\":0"));
	rejected(replaced(initial,"\"exempt_root\":true","\"exempt_root\":true,\"exempt_root\":true"));
	rejected(replaced(initial,"\"id\":0","\"id\":0,\"uid\":10001"));
	for(const auto* id:{"-1","4294967295","4294967296","0.1","\"0\"","null","true"})
		rejected(replaced(initial,"\"id\":0",std::string("\"id\":")+id));
	for(const auto* name:{"","\\u0000","\\u000a","\\u007f","\\ud800"})
		rejected(replaced(initial,"\"name\":\"默认\"",std::string("\"name\":\"")+name+"\""));
	rejected(replaced(initial,"默认",std::string("bad")+char(0xff)));
	rejected(replaced(initial,"默认",std::string(129,'a')));
	rejected(replaced(initial,"\"paths\":[]","\"paths\":[],\"paths\":[]"));
	rejected(replaced(initial,"\"paths\":[]","\"paths\":null"));
	rejected(replaced(initial,"\"maps\":[],",""));
	rejected(replaced(initial,"\"packages\":[]","\"packages\":[\"app.alpha\"]"));
	rejected(replaced(encoded,"\"ino\":\"18446744073709551615\"","\"ino\":18446744073709551615"));
	rejected(replaced(encoded,"\"ino\":\"18446744073709551615\"","\"ino\":\"18446744073709551616\""));
	rejected(replaced(encoded,"\"dev_encoded\":\"4294967295\"","\"dev_encoded\":\"4294967296\""));
	rejected(replaced(encoded,"\"size\":\"4096\"","\"size\":\"-1\""));
	rejected(replaced(encoded,"\"ctime_sec\":\"-9223372036854775808\"","\"ctime_sec\":\"-9223372036854775809\""));
	rejected(replaced(encoded,"\"ctime_nsec\":\"999999999\"","\"ctime_nsec\":\"1000000000\""));
	rejected(replaced(encoded,"\"blksize\":\"4096\"","\"blksize\":\"0\""));
	rejected(replaced(encoded,"\"ino\":\"18446744073709551615\"","\"flags\":\"1\""));
	rejected(replaced(encoded,"\"ino\":\"18446744073709551615\"","\"ino\":\"1\",\"ino\":\"2\""));
	std::string oversized(524289,' ');rejected(oversized);

	for(const auto* path:{"/","relative","/a/","//a","/a//b","/a/./b","/a/../b","/a\n","/a\x7f"}) {
		auto bad=m::initial_config();bad.profiles[0].rules.paths={path};invalid(bad);
	}
	config=m::initial_config();config.profiles[0].rules.paths={"/"+std::string(254,'a')};
	std::string error;CHECK(m::validate_config(config,error));CHECK(!m::serialize_config(config).empty());
	config.profiles[0].rules.paths[0]+='a';invalid(config);
	config=m::initial_config();config.profiles[0].rules.paths={"/owned/a","/owned/a"};invalid(config);
	config=m::initial_config();config.profiles[0].rules.maps={"/owned/a","/owned/a"};invalid(config);
	config=m::initial_config();config.profiles[0].rules.mounts={"/owned/a","/owned/a"};invalid(config);
	config=m::initial_config();config.profiles[0].rules.redirects={{"/a","/b"},{"/c","/b"}};invalid(config);
	config.profiles[0].rules.redirects={{"/a","/b"},{"/b","/c"}};invalid(config);
	config.profiles[0].rules.redirects={{"/a","/a"}};invalid(config);
	config=configured();config.profiles[1].rules.kstats[0].values.flags=0;invalid(config);
	config=configured();config.profiles[1].rules.kstats[0].values.atime_sec=1;invalid(config);
	config=configured();config.profiles[1].rules.kstats[0].values.reserved=1;invalid(config);
	config=configured();config.profiles[1].rules.kstats[0].values.flags|=1U<<12;invalid(config);
	config=configured();config.profiles[1].rules.kstats.push_back(config.profiles[1].rules.kstats[0]);invalid(config);
	config=m::initial_config();config.profiles[0].id=1;invalid(config);
	config=m::initial_config();config.profiles.push_back(config.profiles[0]);invalid(config);
	config=configured();config.profiles.push_back({8,"other",{"app.uninstalled"},{}});invalid(config);
	config=configured();config.profiles[1].packages.push_back("app.alpha");invalid(config);
	config=m::initial_config();config.subjects.whitelist_packages={"app.a","app.a"};invalid(config);
	config=m::initial_config();config.subjects.blacklist_packages={"bad-package"};invalid(config);
}

static void compilation() {
	auto facts=inventory();auto config=configured();std::string error;
	auto output=std::make_unique<skp_full_objects_config>();
	CHECK(m::compile_config(config,facts,*output,error));CHECK(error.empty());CHECK(!skp_full_objects_validate(output.get()));
	const auto& subjects=output->objects.paths.subjects;
	CHECK(subjects.facts_generation==77&&subjects.profile_count==2&&subjects.profiles[0]==0&&subjects.profiles[1]==7);
	CHECK(subjects.binding_count==1&&subjects.bindings[0].uid==10001&&subjects.bindings[0].profile_id==7);
	CHECK(subjects.whitelist_count==1&&subjects.whitelist[0]==10002);
	CHECK(subjects.blacklist_count==1&&subjects.blacklist[0]==10001);
	CHECK(subjects.system_app_count==1&&subjects.system_apps[0]==10001);
	CHECK(output->objects.paths.path_count==3&&output->objects.kstat_count==1&&output->objects.map_count==1);
	CHECK(output->redirect_count==1&&output->mount_count==1);
	CHECK(output->objects.kstats[0].profile_id==7&&output->objects.kstats[0].values.ino==UINT64_MAX);
	CHECK(output->objects.kstats[0].values.flags==config.profiles[1].rules.kstats[0].values.flags);
	CHECK(output->objects.kstats[0].values.atime_sec==0&&output->objects.kstats[0].values.reserved==0);
	CHECK(output->objects.maps[0].profile_id==7&&output->redirects[0].profile_id==7&&output->mounts[0].profile_id==7);
	skp_subject_context context{};context.actual_uid=10001;
	CHECK(skp_subject_evaluate(&subjects,&context).profile_id==7);
	context.actual_uid=10002;CHECK(!skp_subject_evaluate(&subjects,&context).applies);
	context.actual_uid=10003;CHECK(skp_subject_evaluate(&subjects,&context).profile_id==0);
	// Selecting one shared member covers its whole UID; no package identity is
	// invented for app.shared, which was not explicitly named in group intent.
	CHECK(subjects.bindings[0].uid==facts.apps[3].uid);
	config.subjects.exempt_system_apps=true;CHECK(m::compile_config(config,facts,*output,error));
	context.actual_uid=10001;CHECK(!skp_subject_evaluate(&output->objects.paths.subjects,&context).applies);
	config.subjects.blacklist=true;CHECK(m::compile_config(config,facts,*output,error));
	CHECK(skp_subject_evaluate(&output->objects.paths.subjects,&context).applies);
	context.actual_uid=10003;CHECK(!skp_subject_evaluate(&output->objects.paths.subjects,&context).applies);
	config=configured();config.profiles[1].packages.push_back("app.shared");
	CHECK(m::compile_config(config,facts,*output,error));CHECK(output->objects.paths.subjects.binding_count==1);
	config=configured();config.profiles.push_back({8,"conflict",{"app.shared"},{}});
	const auto old=*output;CHECK(!m::compile_config(config,facts,*output,error));
	CHECK(error=="shared_uid_profile_conflict"&&std::memcmp(&old,output.get(),sizeof(old))==0);
	config=configured();config.object_rules_enabled=false;
	const auto saved=m::serialize_config(config);CHECK(m::compile_config(config,facts,*output,error));
	CHECK(output->objects.paths.path_count==0&&output->objects.kstat_count==0&&output->objects.map_count==0);
	CHECK(output->redirect_count==0&&output->mount_count==0&&output->objects.paths.subjects.binding_count==1);
	CHECK(m::serialize_config(config)==saved&&saved.find("/owned/source")!=std::string::npos);
	config=configured();config.upstream=true;CHECK(m::compile_config(config,facts,*output,error));
	CHECK(output->objects.paths.path_count==0&&output->redirect_count==0&&output->mount_count==0);
	// Every configured field is still checked while disabled or dormant.
	config.profiles[1].rules.paths.push_back("/bad/../path");invalid(config);
	config=configured();facts.apps.erase(std::remove_if(facts.apps.begin(),facts.apps.end(),[](const m::App& app){return app.package=="app.alpha"||app.package=="app.shared";}),facts.apps.end());
	facts.generation=78;refresh(facts);
	CHECK(m::compile_config(config,facts,*output,error));CHECK(output->objects.paths.subjects.binding_count==0);
	CHECK(m::serialize_config(config).find("app.alpha")!=std::string::npos);
	facts.apps.push_back({"app.new",10001,false});refresh(facts);
	CHECK(m::compile_config(config,facts,*output,error));CHECK(output->objects.paths.subjects.binding_count==0);
	facts.apps.push_back({"app.alpha",10009,false});facts.generation=79;refresh(facts);
	CHECK(m::compile_config(config,facts,*output,error));
	CHECK(output->objects.paths.subjects.binding_count==1&&output->objects.paths.subjects.bindings[0].uid==10009);
	for(unsigned kind=0;kind<5;++kind) {
		auto bad=inventory();
		if(kind==0)bad.complete=false;
		else if(kind==1)bad.generation=0;
		else if(kind==2)bad.apps[0].uid=110001;
		else if(kind==3)bad.apps.push_back(bad.apps[0]);
		else bad.apps[0].package="invalid-package";
		refresh(bad);
		const auto preserved=*output;CHECK(!m::compile_config(config,bad,*output,error));
		CHECK(!error.empty()&&std::memcmp(&preserved,output.get(),sizeof(preserved))==0);
	}
	// No standalone UID arrays, PID origins or stale values are serialized.
	CHECK(saved.find("facts_generation")==std::string::npos&&saved.find("\"uid\"")==std::string::npos);
	CHECK(saved.find("\"flags\"")==std::string::npos&&saved.find("\"pid\"")==std::string::npos);
}

static void capacities_and_values() {
	auto config=m::initial_config();std::string error;
	for(unsigned id=1;id<32;++id)config.profiles.push_back({id,"profile"+std::to_string(id),{}, {}});
	CHECK(m::validate_config(config,error));config.profiles.push_back({32,"excess",{}, {}});invalid(config);
	config=m::initial_config();
	for(unsigned index=0;index<128;++index)config.profiles[0].rules.paths.push_back("/owned/p"+std::to_string(index));
	CHECK(m::validate_config(config,error));config.profiles[0].rules.paths.push_back("/owned/excess");invalid(config);
	for(unsigned family=0;family<4;++family) {
		config=m::initial_config();const unsigned limit=family==0?32:64;
		for(unsigned index=0;index<=limit;++index) {
			const auto path="/owned/"+std::to_string(index);
			if(family==0) {m::KstatRule rule;rule.path=path;rule.values.flags=1;rule.values.ino=index;config.profiles[0].rules.kstats.push_back(rule);}
			else if(family==1)config.profiles[0].rules.maps.push_back(path);
			else if(family==2)config.profiles[0].rules.redirects.push_back({path,"/targets/"+std::to_string(index)});
			else config.profiles[0].rules.mounts.push_back(path);
			if(index+1==limit)CHECK(m::validate_config(config,error));
		}
		invalid(config);
	}
	config=configured();config.profiles[1].rules.kstats.clear();
	const char* names[]={"ino","dev_encoded","nlink","size","atime_sec","atime_nsec","mtime_sec","mtime_nsec","ctime_sec","ctime_nsec","blocks","blksize"};
	const char* values[]={"18446744073709551615","4294967295","4294967295","9223372036854775807","-9223372036854775808","999999999","9223372036854775807","0","-1","1","9223372036854775807","2147483647"};
	for(unsigned bit=0;bit<12;++bit) {
		const auto base=m::serialize_config(config);
		const auto text=replaced(base,"\"kstats\":[]",std::string("\"kstats\":[{\"path\":\"/owned/value\",\"values\":{\"")+names[bit]+"\":\""+values[bit]+"\"}}]");
		auto value=parsed(text);CHECK(value.profiles[0].rules.kstats.size()==1);
		CHECK(value.profiles[0].rules.kstats[0].values.flags==(1U<<bit));
		CHECK(m::serialize_config(parsed(m::serialize_config(value)))==m::serialize_config(value));
	}
	config=m::initial_config();config.profiles.push_back({7,"packages",{}, {}});
	for(unsigned index=0;index<512;++index)config.profiles[1].packages.push_back("app.p"+std::to_string(index));
	CHECK(m::validate_config(config,error));
	config.profiles[1].packages.push_back("app.extra");invalid(config);
	config=m::initial_config();
	for(unsigned index=0;index<128;++index)config.subjects.whitelist_packages.push_back("app.p"+std::to_string(index));
	CHECK(m::validate_config(config,error));config.subjects.whitelist_packages.push_back("app.extra");invalid(config);
	config=configured();const auto before=m::serialize_config(config);
	CHECK(!m::import_schema8("version 8\nrevision 1\npath_loop \"/a\"\n",config,error));
	CHECK(error=="schema8_explicit_migration_required"&&m::serialize_config(config)==before);
}

static void manager_bootstrap() {
	std::string error;auto facts=inventory();
	auto output=std::make_unique<skp_full_objects_config>();
	for(const auto* path:{"/proc",SKP_POLICY_NODE}) {
		auto config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;
		config.profiles[0].rules.paths={path};
		// Root exemption applies before a profile is selected in whitelist mode.
		CHECK(m::compile_config(config,facts,*output,error));
		config.subjects.exempt_root=false;
		const auto preserved=*output;
		CHECK(!m::compile_config(config,facts,*output,error));
		CHECK(error=="manager_bootstrap_path_hidden");
		CHECK(std::memcmp(&preserved,output.get(),sizeof(preserved))==0);
		// A non-root application's custom profile may still hide /proc while
		// a pre-session root client uses the unobstructed default profile.
		config.profiles[0].rules.paths.clear();
		config.profiles.push_back({7,"custom",{"app.alpha"},{}});
		config.profiles[1].rules.paths={path};
		CHECK(m::compile_config(config,facts,*output,error));
		// Broad exemption flags are ignored in blacklist mode, but root is not
		// intercepted unless an actual root UID belongs to its selected list.
		config.profiles[0].rules.paths={path};config.subjects.blacklist=true;
		config.subjects.blacklist_packages={"app.alpha"};
		CHECK(m::compile_config(config,facts,*output,error));
		config.subjects.blacklist=false;config.profiles[0].rules.paths.clear();
		config.subjects.exempt_root=true;
		auto root_facts=facts;root_facts.apps.push_back({"app.root",0,false});refresh(root_facts);
		config.profiles[1].packages={"app.root"};
		CHECK(m::compile_config(config,root_facts,*output,error));
		config.subjects.exempt_root=false;
		CHECK(!m::compile_config(config,root_facts,*output,error));
		CHECK(error=="manager_bootstrap_path_hidden");
		config.subjects.blacklist=true;config.subjects.blacklist_packages={"app.root"};
		config.subjects.exempt_root=true;
		CHECK(!m::compile_config(config,root_facts,*output,error));
		CHECK(error=="manager_bootstrap_path_hidden");
		// Dormant rules are not installed, so they cannot block this bootstrap.
		config.object_rules_enabled=false;CHECK(m::compile_config(config,root_facts,*output,error));
		config.object_rules_enabled=true;config.upstream=true;
		CHECK(m::compile_config(config,root_facts,*output,error));
	}
}

static std::uint32_t path_index(const skp_full_objects_config& wire,std::uint32_t profile,const std::string& path) {
	for(std::uint32_t i=0;i<wire.objects.paths.path_count;++i)
		if(wire.objects.paths.rules[i].profile_id==profile&&wire.objects.paths.rules[i].path==path)return i;
	CHECK(false);return 0;
}
static bool path_applies(const skp_full_objects_config& wire,const skp_path_scope_table& table,
		std::uint32_t profile,const std::string& path,std::uint32_t uid) {
	skp_subject_context context{};context.actual_uid=uid;
	return skp_path_scope_applies(&wire.objects.paths,&table,path_index(wire,profile,path),&context)!=0;
}
static m::Config scoped_config() {
	auto config=configured();
	m::PathScope first;first.profile_id=7;first.path="/owned/中文 空格";
	first.subjects.blacklist=true;first.subjects.blacklist_packages={"app.uninstalled","app.beta"};
	first.subjects.whitelist_packages={"app.shared"};
	m::PathScope second;second.path="/owned/default";second.subjects.exempt_root=false;
	second.subjects.exempt_system_processes=false;second.subjects.exempt_system_apps=false;
	second.subjects.whitelist_packages={"app.shared"};
	config.path_scopes={first,second};return config;
}
static void scope_parsing_and_legacy() {
	auto config=scoped_config();std::string error;
	const auto encoded=m::serialize_config(config);CHECK(!encoded.empty());
	CHECK(encoded.find("\"schema\":10")!=std::string::npos);
	CHECK(m::serialize_config(parsed(encoded))==encoded);
	auto restored=parsed(encoded);CHECK(restored.path_scopes.size()==2);
	CHECK(restored.path_scopes[0].profile_id==0&&restored.path_scopes[0].path=="/owned/default");
	CHECK(restored.path_scopes[1].subjects.blacklist&&restored.path_scopes[1].subjects.whitelist_packages==std::vector<std::string>{"app.shared"});
	CHECK(restored.path_scopes[1].subjects.blacklist_packages==std::vector<std::string>({"app.beta","app.uninstalled"}));
	std::reverse(config.path_scopes.begin(),config.path_scopes.end());
	std::reverse(config.path_scopes[1].subjects.blacklist_packages.begin(),config.path_scopes[1].subjects.blacklist_packages.end());
	std::reverse(config.profiles.begin(),config.profiles.end());
	CHECK(m::serialize_config(config)==encoded);

	const auto original=configured();const auto modern=m::serialize_config(original);
	const auto legacy=replaced(replaced(modern,"\"schema\":10","\"schema\":9"),",\"path_scopes\":[]","");
	const auto imported=parsed(legacy);CHECK(imported.path_scopes.empty());
	CHECK(m::serialize_config(imported)==modern);
	CHECK(imported.profiles[0].rules.paths==original.profiles[0].rules.paths);
	CHECK(imported.profiles[1].packages==std::vector<std::string>({"app.alpha","app.uninstalled"}));
	auto facts=inventory();auto before=std::make_unique<skp_full_objects_config>(),after=std::make_unique<skp_full_objects_config>();
	auto table=std::make_unique<skp_path_scope_table>();
	CHECK(m::compile_config(original,facts,*before,error));CHECK(m::compile_config(imported,facts,*after,error,table.get()));
	CHECK(!std::memcmp(before.get(),after.get(),sizeof(*before)));
	CHECK(table->version==SKP_PATH_SCOPES_VERSION&&table->path_count==3);
	for(const auto& scope:table->rules)CHECK(scope.kind==SKP_PATH_SCOPE_INHERIT);
	CHECK(!path_applies(*after,*table,0,"/owned/default",10001));
	CHECK(path_applies(*after,*table,7,"/owned/z",10001));
	CHECK(!path_applies(*after,*table,7,"/owned/z",10003));
	CHECK(after->objects.kstat_count==1&&after->objects.map_count==1&&after->redirect_count==1&&after->mount_count==1);

	rejected(replaced(modern,"\"schema\":10","\"schema\":9"));
	rejected(replaced(legacy,"\"schema\":9","\"schema\":10"));
	rejected(replaced(encoded,"\"path_scopes\":[","\"path_scopes\":null,\"ignored\":["));
	rejected(replaced(encoded,"\"path_scopes\":[","\"path_scopes\":[],\"path_scopes\":["));
	rejected(replaced(encoded,"\"profile_id\":0","\"profile_id\":\"0\""));
	rejected(replaced(encoded,"\"profile_id\":0","\"profile_id\":4294967295"));
	rejected(replaced(encoded,"\"profile_id\":0","\"profile_id\":0,\"uid\":10001"));
	rejected(replaced(encoded,"\"path\":\"/owned/default\",\"subjects\":", "\"path\":\"/owned/default\",\"subjects\":null,\"extra\":"));
	rejected(replaced(encoded,"\"subjects\":{\"mode\":\"whitelist\"","\"subjects\":{\"mode\":\"bogus\""));
	rejected(replaced(encoded,"\"subjects\":{\"mode\":\"blacklist\"","\"subjects\":{\"mode\":\"bogus\""));
	const auto empty=m::serialize_config(m::initial_config());
	rejected(replaced(empty,"\"path_scopes\":[]","\"path_scopes\":null"));
	rejected(replaced(empty,"\"path_scopes\":[]","\"path_scopes\":{}"));
	std::string excess="[";for(unsigned i=0;i<129;++i){if(i)excess+=',';excess+="{}";}excess+=']';
	rejected(replaced(empty,"\"path_scopes\":[]","\"path_scopes\":"+excess));
	excess="[";for(unsigned i=0;i<129;++i){if(i)excess+=',';excess+=m::quote("app.excess"+std::to_string(i));}excess+=']';
	rejected(replaced(encoded,"\"blacklist_packages\":[\"app.beta\",\"app.uninstalled\"]","\"blacklist_packages\":"+excess));

	config=scoped_config();config.path_scopes.push_back(config.path_scopes[0]);invalid(config);
	config=scoped_config();config.path_scopes[0].profile_id=19;invalid(config);
	config=scoped_config();config.path_scopes[0].path="/owned/stat";invalid(config);
	config=scoped_config();config.path_scopes[0].path="/owned/default";invalid(config);
	config=scoped_config();config.path_scopes[0].path="/bad/../path";invalid(config);
	config=scoped_config();config.profiles[1].rules.paths.clear();invalid(config);
	config=scoped_config();config.path_scopes[0].subjects.blacklist_packages={"app.beta","app.beta"};invalid(config);
	config=scoped_config();config.path_scopes[0].subjects.whitelist_packages={"not-a-package"};invalid(config);
	config=scoped_config();config.upstream=true;config.path_scopes[0].profile_id=91;invalid(config);
	config=scoped_config();config.object_rules_enabled=false;config.path_scopes[0].subjects.whitelist_packages={"invalid-package"};invalid(config);
}
static void scope_compilation() {
	auto facts=inventory();auto config=scoped_config();std::string error;
	auto wire=std::make_unique<skp_full_objects_config>(),baseline=std::make_unique<skp_full_objects_config>();
	auto table=std::make_unique<skp_path_scope_table>();
	auto inherited=config;inherited.path_scopes.clear();CHECK(m::compile_config(inherited,facts,*baseline,error));
	CHECK(!m::compile_config(config,facts,*wire,error)&&error=="path_scope_output_required");
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(error.empty());
	CHECK(!std::memcmp(wire.get(),baseline.get(),sizeof(*wire)));
	CHECK(!skp_path_scopes_validate(&wire->objects.paths,table.get()));
	CHECK(table->path_count==wire->objects.paths.path_count&&table->version==SKP_PATH_SCOPES_VERSION&&!table->reserved);
	const auto custom=path_index(*wire,7,"/owned/中文 空格"),ordinary=path_index(*wire,7,"/owned/z"),other=path_index(*wire,0,"/owned/default");
	CHECK(table->rules[custom].kind==SKP_PATH_SCOPE_CUSTOM&&table->rules[ordinary].kind==SKP_PATH_SCOPE_INHERIT);
	CHECK(table->rules[custom].mode==SKP_SUBJECT_BLACKLIST&&table->rules[custom].flags==SKP_SUBJECT_EXEMPT_ALL);
	CHECK(table->rules[custom].blacklist_count==1&&table->rules[custom].blacklist[0]==10002);
	CHECK(table->rules[custom].whitelist_count==1&&table->rules[custom].whitelist[0]==10001);
	CHECK(path_applies(*wire,*table,7,"/owned/中文 空格",10002));
	skp_subject_context excluded{};excluded.actual_uid=10002;
	CHECK(!skp_subject_evaluate(&wire->objects.paths.subjects,&excluded).applies);
	CHECK(!path_applies(*wire,*table,7,"/owned/中文 空格",10001));
	CHECK(path_applies(*wire,*table,7,"/owned/z",10001));
	CHECK(!path_applies(*wire,*table,7,"/owned/z",10002));
	CHECK(!path_applies(*wire,*table,7,"/owned/z",10003));
	CHECK(!path_applies(*wire,*table,0,"/owned/default",10001));
	CHECK(path_applies(*wire,*table,0,"/owned/default",10002));
	CHECK(path_applies(*wire,*table,0,"/owned/default",0));
	CHECK(path_applies(*wire,*table,0,"/owned/default",1000));
	CHECK(table->rules[other].whitelist_count==1&&table->rules[other].whitelist[0]==10001);
	// All four other families and canonical global subjects remain identical.
	CHECK(wire->objects.kstats[0].values.ino==UINT64_MAX&&wire->objects.kstats[0].profile_id==7);
	CHECK(wire->objects.maps[0].profile_id==7&&wire->redirects[0].profile_id==7&&wire->mounts[0].profile_id==7);
	skp_subject_context context{};context.actual_uid=10002;context.precise_manager=1;
	CHECK(!skp_path_scope_applies(&wire->objects.paths,table.get(),custom,&context));
	const auto saved=m::serialize_config(config);const auto preserved=*wire;const auto old_table=*table;
	auto invalid_facts=facts;invalid_facts.generation=0;
	CHECK(!m::compile_config(config,invalid_facts,*wire,error,table.get()));
	CHECK(!std::memcmp(&preserved,wire.get(),sizeof(preserved))&&!std::memcmp(&old_table,table.get(),sizeof(old_table)));
	for(const bool upstream:{false,true}) {
		auto dormant=config;dormant.upstream=upstream;dormant.object_rules_enabled=upstream;
		CHECK(!m::compile_config(dormant,facts,*wire,error)&&error=="path_scope_output_required");
		CHECK(m::compile_config(dormant,facts,*wire,error,table.get()));
		CHECK(table->version==SKP_PATH_SCOPES_VERSION&&table->path_count==0&&wire->objects.paths.path_count==0);
		for(const auto& scope:table->rules)CHECK(scope.kind==0&&scope.mode==0&&scope.flags==0&&!scope.whitelist_count&&!scope.blacklist_count);
		CHECK(parsed(m::serialize_config(dormant)).path_scopes.size()==2);
	}
	CHECK(m::serialize_config(config)==saved&&saved.find("\"uid\"")==std::string::npos&&saved.find("facts_generation")==std::string::npos);
	// Recycled UIDs are never carried over from a previously compiled scope.
	facts.apps.erase(std::remove_if(facts.apps.begin(),facts.apps.end(),[](const m::App& app){return app.package=="app.beta";}),facts.apps.end());facts.generation++;refresh(facts);
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(table->rules[custom].blacklist_count==0);
	facts.apps.push_back({"app.recycled",10002,false});refresh(facts);
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(!path_applies(*wire,*table,7,"/owned/中文 空格",10002));
	facts.apps.push_back({"app.beta",10123,false});facts.generation++;refresh(facts);
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(table->rules[custom].blacklist_count==1&&table->rules[custom].blacklist[0]==10123);
	CHECK(m::serialize_config(config)==saved);
}
static void scope_categories_overlap_and_capacity() {
	std::string error;auto facts=inventory();auto config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;
	config.profiles[0].rules.paths={"/owned/scope"};
	m::PathScope scope;scope.path="/owned/scope";config.path_scopes={scope};
	auto wire=std::make_unique<skp_full_objects_config>();auto table=std::make_unique<skp_path_scope_table>();
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));
	CHECK(!path_applies(*wire,*table,0,scope.path,0));CHECK(!path_applies(*wire,*table,0,scope.path,1000));
	CHECK(!path_applies(*wire,*table,0,scope.path,10001));CHECK(path_applies(*wire,*table,0,scope.path,10003));
	config.path_scopes[0].subjects.exempt_root=false;CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(path_applies(*wire,*table,0,scope.path,0));
	config.path_scopes[0].subjects.exempt_system_processes=false;CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(path_applies(*wire,*table,0,scope.path,1000));
	config.path_scopes[0].subjects.exempt_system_apps=false;CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(path_applies(*wire,*table,0,scope.path,10001));
	config.path_scopes[0].subjects.whitelist_packages={"app.alpha","app.shared"};CHECK(m::compile_config(config,facts,*wire,error,table.get()));
	CHECK(table->rules[0].whitelist_count==1&&!path_applies(*wire,*table,0,scope.path,10001));
	config.path_scopes[0].subjects.blacklist=true;config.path_scopes[0].subjects.blacklist_packages={"app.alpha"};
	config.path_scopes[0].subjects.exempt_system_apps=true;CHECK(m::compile_config(config,facts,*wire,error,table.get()));
	CHECK(path_applies(*wire,*table,0,scope.path,10001)&&!path_applies(*wire,*table,0,scope.path,10003));

	config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;
	config.profiles[0].rules.paths={"/owned/same"};config.profiles.push_back({7,"other",{"app.alpha"},{}});config.profiles[1].rules.paths={"/owned/same"};
	scope.path="/owned/same";scope.subjects.blacklist=true;scope.subjects.blacklist_packages={"app.beta"};config.path_scopes={scope};
	scope.profile_id=7;scope.subjects.blacklist_packages={"app.gamma"};config.path_scopes.push_back(scope);
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));
	skp_group_path_object objects[2]{};
	for(unsigned i=0;i<2;++i){objects[i].profile_id=wire->objects.paths.rules[i].profile_id;objects[i].dev=4;objects[i].ino=87;std::strcpy(objects[i].name,"same");}
	skp_subject_context context{};context.actual_uid=10002;CHECK(skp_path_scopes_inode_hidden(&wire->objects.paths,table.get(),objects,2,&context,4,87));
	context.actual_uid=10003;CHECK(skp_path_scopes_inode_hidden(&wire->objects.paths,table.get(),objects,2,&context,4,87));
	context.actual_uid=10001;CHECK(!skp_path_scopes_inode_hidden(&wire->objects.paths,table.get(),objects,2,&context,4,87));
	CHECK(!path_applies(*wire,*table,7,"/owned/same",10002)&&path_applies(*wire,*table,7,"/owned/same",10003));

	config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;
	for(unsigned i=0;i<128;++i){const auto path="/owned/p"+std::to_string(i);config.profiles[0].rules.paths.push_back(path);m::PathScope item;item.path=path;item.subjects.blacklist=true;item.subjects.blacklist_packages={"app.beta"};config.path_scopes.push_back(item);}
	CHECK(m::compile_config(config,facts,*wire,error,table.get()));CHECK(table->path_count==128);
	for(unsigned i=0;i<128;++i)CHECK(table->rules[i].kind==SKP_PATH_SCOPE_CUSTOM&&table->rules[i].blacklist_count==1);
	config.path_scopes.push_back(config.path_scopes[0]);invalid(config);
	config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;config.profiles[0].rules.paths={"/owned/list"};scope={};scope.path="/owned/list";
	for(unsigned i=0;i<128;++i){const auto name="app.member"+std::to_string(i);scope.subjects.blacklist_packages.push_back(name);facts.apps.push_back({name,20000+i,false});}
	scope.subjects.blacklist=true;config.path_scopes={scope};refresh(facts);CHECK(m::compile_config(config,facts,*wire,error,table.get()));
	CHECK(table->rules[0].blacklist_count==128&&table->rules[0].blacklist[0]==20000&&table->rules[0].blacklist[127]==20127);
	config.path_scopes[0].subjects.blacklist_packages.push_back("app.excess");invalid(config);
	// Individual legal caps must not create a 'valid' Config that serializes to
	// empty JSON because the aggregate persisted intent exceeds 512 KiB.
	config=m::initial_config();
	for(unsigned p=0;p<16;++p) {
		m::PathScope item;item.path="/owned/size"+std::to_string(p);config.profiles[0].rules.paths.push_back(item.path);
		for(unsigned i=0;i<128;++i){const auto name="app."+std::string(230,'a')+std::to_string(i);item.subjects.whitelist_packages.push_back(name);item.subjects.blacklist_packages.push_back(name);}
		config.path_scopes.push_back(item);
	}
	CHECK(!m::validate_config(config,error)&&error=="config_capacity_exceeded");CHECK(m::serialize_config(config).empty());
	config.upstream=false;config.object_rules_enabled=false;CHECK(!m::validate_config(config,error)&&error=="config_capacity_exceeded");
	const auto old_wire=*wire;const auto old_table=*table;
	CHECK(!m::compile_config(config,facts,*wire,error,table.get())&&error=="config_capacity_exceeded");
	CHECK(!std::memcmp(&old_wire,wire.get(),sizeof(old_wire))&&!std::memcmp(&old_table,table.get(),sizeof(old_table)));
}
static void scope_bootstrap() {
	auto facts=inventory();facts.apps.push_back({"app.root",0,false});refresh(facts);std::string error;
	auto wire=std::make_unique<skp_full_objects_config>();auto table=std::make_unique<skp_path_scope_table>();
	for(const auto* path:{"/proc",SKP_POLICY_NODE}) {
		auto config=m::initial_config();config.upstream=false;config.object_rules_enabled=true;
		config.profiles.push_back({7,"app",{"app.alpha"},{}});config.profiles[1].rules.paths={path};
		m::PathScope scope;scope.profile_id=7;scope.path=path;scope.subjects.exempt_root=false;config.path_scopes={scope};
		CHECK(!m::compile_config(config,facts,*wire,error,table.get())&&error=="manager_bootstrap_path_hidden");
		config.path_scopes[0].subjects.exempt_root=true;CHECK(m::compile_config(config,facts,*wire,error,table.get()));
		config.subjects.exempt_root=false;config.profiles[0].rules.paths={path};
		m::PathScope root_scope;root_scope.path=path;root_scope.subjects.exempt_root=true;config.path_scopes.push_back(root_scope);
		CHECK(m::compile_config(config,facts,*wire,error,table.get()));
		config.path_scopes[0].subjects.blacklist=true;config.path_scopes[0].subjects.blacklist_packages={"app.root"};
		CHECK(!m::compile_config(config,facts,*wire,error,table.get())&&error=="manager_bootstrap_path_hidden");
		config.path_scopes[0].subjects.blacklist_packages={"app.alpha"};CHECK(m::compile_config(config,facts,*wire,error,table.get()));
		config.path_scopes[1].subjects.exempt_root=false;
		const auto preserved=*wire;const auto saved=*table;
		CHECK(!m::compile_config(config,facts,*wire,error,table.get())&&error=="manager_bootstrap_path_hidden");
		CHECK(!std::memcmp(&preserved,wire.get(),sizeof(preserved))&&!std::memcmp(&saved,table.get(),sizeof(saved)));
		config.object_rules_enabled=false;CHECK(m::compile_config(config,facts,*wire,error,table.get())&&table->path_count==0);
	}
}

int main() {
	parsing();compilation();capacities_and_values();manager_bootstrap();
	scope_parsing_and_legacy();scope_compilation();scope_categories_overlap_and_capacity();scope_bootstrap();
	std::printf("MANAGEMENT_CONFIG_HOST checks=%u passed=true kernel_calls=false production_source=true\n",checks);
	return 0;
}
