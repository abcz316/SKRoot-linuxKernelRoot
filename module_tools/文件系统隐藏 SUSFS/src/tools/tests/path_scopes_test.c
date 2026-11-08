// SPDX-License-Identifier: GPL-2.0-only
/* Production pure path selectors, synthetic identities/keys; no kernel calls. */
#include "../../kernel/skp_path_scopes.h"
#include "../../kernel/skp_full_objects.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct skp_path_scope) == 1056, "scope width");
_Static_assert(sizeof(struct skp_path_scope_table) == 135184, "table width");
_Static_assert(offsetof(struct skp_path_scope, whitelist) == 32, "scope list offset");
_Static_assert(offsetof(struct skp_path_scope, blacklist) == 544, "scope second list offset");
_Static_assert(offsetof(struct skp_path_scope_table, rules) == 16, "table rules offset");
_Static_assert(sizeof(struct skp_group_paths_config) == 43208, "old path ABI unchanged");

static unsigned checks;
static struct skp_group_paths_config config, saved_config;
static struct skp_path_scope_table scopes, saved_scopes;
static struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
static void expect(int value, const char *label)
{
	++checks;
	if (!value) { fprintf(stderr, "FAIL PATH_SCOPES check=%u %s\n", checks, label); exit(1); }
}
static struct skp_subject_context caller(skp_subject_u32 uid)
{
	struct skp_subject_context context = {0};
	context.actual_uid = uid;
	return context;
}
static void fixture(void)
{
	unsigned i;
	memset(&config, 0, sizeof(config)); memset(&scopes, 0, sizeof(scopes)); memset(objects, 0, sizeof(objects));
	config.version = SKP_GROUP_PATHS_VERSION; config.path_count = 4;
	config.subjects.version = SKP_SUBJECT_POLICY_VERSION; config.subjects.facts_generation = 42;
	config.subjects.profile_count = 2; config.subjects.profiles[1] = 7;
	config.subjects.binding_count = 1; config.subjects.bindings[0].uid = 10001; config.subjects.bindings[0].profile_id = 7;
	config.subjects.flags = SKP_SUBJECT_EXEMPT_ALL;
	config.subjects.system_app_count = 1; config.subjects.system_apps[0] = 10002;
	config.subjects.whitelist_count = 1; config.subjects.whitelist[0] = 10003;
	config.subjects.blacklist_count = 1; config.subjects.blacklist[0] = 10002;
	strcpy(config.rules[0].path, "/owned/a"); strcpy(config.rules[1].path, "/owned/b");
	strcpy(config.rules[2].path, "/owned/a"); strcpy(config.rules[3].path, "/owned/c");
	config.rules[1].profile_id = config.rules[2].profile_id = 7;
	for (i = 0; i < 4; ++i) {
		objects[i].profile_id = config.rules[i].profile_id; objects[i].dev = 10;
		objects[i].ino = i == 2 ? 100 : 100 + i;
		strcpy(objects[i].name, i == 0 || i == 2 ? "a" : i == 1 ? "b" : "c");
	}
	scopes.version = SKP_PATH_SCOPES_VERSION; scopes.path_count = config.path_count;
	expect(!skp_group_paths_objects_validate(&config, objects, 4), "canonical path fixture accepted with cross-profile same object");
	expect(!skp_path_scopes_validate(&config, &scopes), "all-inherit scope table accepted");
}
static void custom(unsigned index, unsigned mode, unsigned flags)
{
	memset(&scopes.rules[index], 0, sizeof(scopes.rules[index]));
	scopes.rules[index].kind = SKP_PATH_SCOPE_CUSTOM; scopes.rules[index].mode = mode; scopes.rules[index].flags = flags;
}
static void scope_result(unsigned index, skp_subject_u32 uid, int applies, const char *label)
{
	struct skp_subject_context context = caller(uid);
	expect(skp_path_scope_applies(&config, &scopes, index, &context) == applies, label);
}
static void validation_tests(void)
{
	unsigned i;
	fixture(); saved_config = config; saved_scopes = scopes;
	expect(skp_path_scopes_validate(NULL, &scopes) == SKP_PATH_SCOPES_ERR_ARGUMENT, "null canonical config refused");
	expect(skp_path_scopes_validate(&config, NULL) == SKP_PATH_SCOPES_ERR_ARGUMENT, "null scopes refused");
	scopes.version++; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_VERSION, "unknown scope version refused"); scopes = saved_scopes;
	scopes.reserved = 1; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_HEADER, "table reserved bits refused"); scopes = saved_scopes;
	for (i = 0; i < 3; ++i) {
		scopes.path_count = i == 0 ? 3 : i == 1 ? 5 : SKP_GROUP_PATHS_MAX + 1;
		expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_COUNT, "scope count must exactly match bounded canonical paths");
	} scopes = saved_scopes;
	config.subjects.facts_generation = 0; expect(skp_path_scopes_validate(&config, &scopes) != 0, "invalid canonical facts refused"); config = saved_config;
	config.rules[0].path[0] = 'x'; expect(skp_path_scopes_validate(&config, &scopes) != 0, "invalid canonical path refused"); config = saved_config;
	scopes.rules[0].kind = 2; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_KIND, "unknown scope kind refused"); scopes = saved_scopes;
	for (i = 0; i < sizeof(struct skp_path_scope); ++i) {
		unsigned char *bytes = (unsigned char *)&scopes.rules[0];
		bytes[i] = 1;
		/* kind=1 by itself is a valid empty custom whitelist. Every other
		 * nonzero byte in a purported inherit payload is noncanonical. */
		if (i) expect(skp_path_scopes_validate(&config, &scopes) != 0, "inherit payload must be entirely zero");
		bytes[i] = 0;
	}
	custom(0, SKP_SUBJECT_WHITELIST, 0); saved_scopes = scopes;
	for (i = 0; i < 3; ++i) { scopes.rules[0].reserved[i] = 1; expect(skp_path_scopes_validate(&config, &scopes) != 0, "each custom reserved word refused"); scopes = saved_scopes; }
	scopes.rules[0].mode = 2; expect(skp_path_scopes_validate(&config, &scopes) != 0, "unknown custom mode refused"); scopes = saved_scopes;
	scopes.rules[0].flags = 8; expect(skp_path_scopes_validate(&config, &scopes) != 0, "unknown custom exemption refused"); scopes = saved_scopes;
	scopes.rules[0].whitelist_count = 129; expect(skp_path_scopes_validate(&config, &scopes) != 0, "oversized whitelist refused"); scopes = saved_scopes;
	scopes.rules[0].blacklist_count = 129; expect(skp_path_scopes_validate(&config, &scopes) != 0, "oversized blacklist refused"); scopes = saved_scopes;
	for (i = 0; i < 2; ++i) {
		skp_subject_u32 *list = i ? scopes.rules[0].blacklist : scopes.rules[0].whitelist;
		skp_subject_u32 *count = i ? &scopes.rules[0].blacklist_count : &scopes.rules[0].whitelist_count;
		*count = 2; list[0] = list[1] = 10001;
		expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_ORDER, "duplicate custom UID refused");
		list[0] = 10002; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_ORDER, "unordered custom UIDs refused");
		list[0] = 0; list[1] = 100000; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_UID, "another Android user cannot enter user0 facts");
		list[1] = SKP_SUBJECT_INVALID_UID; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_UID, "invalid custom UID refused");
		list[1] = 99999; expect(!skp_path_scopes_validate(&config, &scopes), "full user0 UID boundary accepted without modulo");
		*count = 1; expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_TAIL, "unused UID tail must be zero");
		memset(list, 0, 128 * sizeof(*list)); *count = 0;
	}
	for (i = 0; i < 128; ++i) scopes.rules[0].whitelist[i] = i;
	scopes.rules[0].whitelist_count = 128; expect(!skp_path_scopes_validate(&config, &scopes), "maximum sorted UID list including root accepted");
	scopes = saved_scopes;
	for (i = config.path_count; i < SKP_GROUP_PATHS_MAX; ++i) {
		scopes.rules[i].kind = SKP_PATH_SCOPE_CUSTOM;
		expect(skp_path_scopes_validate(&config, &scopes) == SKP_PATH_SCOPES_ERR_TAIL, "every unused scope slot must be zero"); scopes.rules[i].kind = 0;
	}
	memset(&config.rules, 0, sizeof(config.rules)); config.path_count = 0;
	memset(scopes.rules, 0, sizeof(scopes.rules)); scopes.path_count = 0;
	expect(!skp_path_scopes_validate(&config, &scopes), "zero paths require a valid empty scope table");
	fixture(); config.path_count = scopes.path_count = SKP_GROUP_PATHS_MAX;
	for (i = 0; i < SKP_GROUP_PATHS_MAX; ++i) {
		memset(&config.rules[i], 0, sizeof(config.rules[i])); snprintf(config.rules[i].path, sizeof(config.rules[i].path), "/owned/path-%u", i);
	}
	expect(!skp_path_scopes_validate(&config, &scopes), "maximum complete path table supported without combination profiles");
}
static void independent_scope_tests(void)
{
	struct skp_subject_context context;
	fixture(); custom(1, SKP_SUBJECT_BLACKLIST, SKP_SUBJECT_EXEMPT_ALL);
	scopes.rules[1].blacklist_count = 2; scopes.rules[1].blacklist[0] = 10001; scopes.rules[1].blacklist[1] = 10004;
	custom(2, SKP_SUBJECT_WHITELIST, 0); scopes.rules[2].whitelist_count = 1; scopes.rules[2].whitelist[0] = 10001;
	custom(3, SKP_SUBJECT_WHITELIST, 0);
	expect(!skp_path_scopes_validate(&config, &scopes), "independent scope payload accepted");
	scope_result(0, 10001, 0, "inherit retains profile mismatch");
	scope_result(1, 10004, 1, "custom blacklist replaces default-profile mismatch");
	scope_result(1, 10002, 0, "custom blacklist does not borrow global blacklist");
	scope_result(2, 10001, 0, "path whitelist exempts its selected UID");
	scope_result(2, 10003, 1, "path whitelist replaces global whitelist and profile gate");
	scope_result(3, 0, 1, "custom flags override global root exemption");
	scope_result(3, 1000, 1, "custom flags override global ordinary-system exemption");
	scope_result(3, 10002, 1, "custom flags override global system-app exemption");
	scopes.rules[3].flags = SKP_SUBJECT_EXEMPT_ROOT; scope_result(3, 0, 0, "path-specific root exemption");
	scopes.rules[3].flags = SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES; scope_result(3, 1000, 0, "path-specific system-process exemption"); scope_result(3, 10000, 1, "app UID boundary is not an ordinary system process");
	scopes.rules[3].flags = SKP_SUBJECT_EXEMPT_SYSTEM_APPS; scope_result(3, 10002, 0, "system-app exemption uses canonical fact table");
	config.subjects.system_apps[0] = 10004; scope_result(3, 10002, 1, "scope never caches independent system-app facts"); scope_result(3, 10004, 0, "updated canonical system facts govern this scope");
	custom(3, SKP_SUBJECT_BLACKLIST, SKP_SUBJECT_EXEMPT_ALL); scopes.rules[3].blacklist_count = 2; scopes.rules[3].blacklist[0] = 0; scopes.rules[3].blacklist[1] = 1000;
	scope_result(3, 0, 1, "blacklist ignores root exemption exactly like original subject policy"); scope_result(3, 1000, 1, "blacklist ignores broad system exemptions");
	config.subjects.mode = SKP_SUBJECT_BLACKLIST;
	scope_result(1, 10001, 1, "custom blacklist replaces global blacklist exclusion");
	scope_result(2, 10004, 1, "custom whitelist replaces global blacklist exclusion");
	context = caller(0); context.worker_verified = 1; context.origin_uid = 10001; context.origin_facts_generation = config.subjects.facts_generation;
	expect(skp_path_scope_applies(&config, &scopes, 1, &context), "verified worker uses complete origin UID for custom blacklist");
	context.origin_facts_generation--;
	expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "stale verified worker fails open before custom scopes");
	context.origin_facts_generation = config.subjects.facts_generation; context.origin_uid = 100001;
	expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "isolated/other-user origin is never guessed");
	context = caller(10001); context.precise_manager = 1;
	expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "exact manager and expired-lease manager context always exempt");
	context.precise_manager = 2; expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "invalid manager context refused");
	context = caller(10001); context.worker_verified = 2; expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "invalid worker flag refused");
	context = caller(SKP_SUBJECT_INVALID_UID); expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "invalid actual identity refused");
	scope_result(1, 110001, 0, "full actual UID is never reduced modulo Android user range");
	custom(3, SKP_SUBJECT_WHITELIST, 0); scope_result(3, 110001, 1, "unknown full UID retains original whitelist semantics without guessed origin");
	context = caller(10001); expect(!skp_path_scope_applies(NULL, &scopes, 1, &context), "hot query null config fails open");
	expect(!skp_path_scope_applies(&config, NULL, 1, &context) && !skp_path_scope_applies(&config, &scopes, 128, &context), "hot query invalid scope pointer/index fails open");
	scopes.rules[1].blacklist_count = 129; expect(!skp_path_scope_applies(&config, &scopes, 1, &context), "hot query malformed bounded scope header fails open");
}
static void overlap_and_parity_tests(void)
{
	static const skp_subject_u32 uids[] = {0,1,9999,10000,10001,10002,10003,10004,110001,SKP_SUBJECT_INVALID_UID};
	unsigned mode, flags, n, manager, worker, i;
	struct skp_subject_context context;
	fixture();
	for (mode = 0; mode < 2; ++mode) for (flags = 0; flags < 8; ++flags)
	for (n = 0; n < sizeof(uids) / sizeof(uids[0]); ++n) for (manager = 0; manager < 2; ++manager) for (worker = 0; worker < 3; ++worker) {
		config.subjects.mode = mode; config.subjects.flags = flags;
		context = caller(uids[n]); context.precise_manager = manager;
		if (worker) { context.worker_verified = 1; context.origin_uid = 10001; context.origin_facts_generation = worker == 1 ? 42 : 41; }
		for (i = 0; i < 4; ++i) {
			const struct skp_subject_decision decision = skp_subject_evaluate(&config.subjects, &context);
			expect(skp_path_scope_applies(&config, &scopes, i, &context) ==
			       (decision.applies && decision.profile_id == config.rules[i].profile_id), "inherit per-rule parity across modes, broad exemptions, managers and workers");
			expect(skp_path_scopes_inode_hidden(&config,&scopes,objects,4,&context,10,objects[i].ino) ==
			       skp_group_paths_inode_hidden(&config,objects,4,&context,10,objects[i].ino), "all-inherit inode query preserves old behavior");
			expect(skp_path_scopes_dirent_hidden(&config,&scopes,objects,4,&context,objects[i].ino,objects[i].name) ==
			       skp_group_paths_dirent_hidden(&config,objects,4,&context,objects[i].ino,objects[i].name), "all-inherit dirent query preserves old behavior");
		}
	}
	fixture(); custom(0, SKP_SUBJECT_BLACKLIST, 0); scopes.rules[0].blacklist_count = 1; scopes.rules[0].blacklist[0] = 10001;
	custom(2, SKP_SUBJECT_BLACKLIST, 0); scopes.rules[2].blacklist_count = 1; scopes.rules[2].blacklist[0] = 10002;
	for (n = 0; n < 3; ++n) {
		context = caller(10001 + n);
		expect(skp_path_scopes_inode_hidden(&config,&scopes,objects,4,&context,10,100) == (n < 2), "cross-profile same inode uses OR of independent rule scopes");
		expect(skp_path_scopes_dirent_hidden_n(&config,&scopes,objects,4,&context,100,"a",1) == (n < 2), "same dirent uses OR without profile-gate fallback");
	}
	context = caller(10001);
	expect(!skp_path_scopes_inode_hidden(&config,&scopes,objects,4,&context,11,100), "inode query retains exact raw device key");
	expect(!skp_path_scopes_inode_hidden(&config,&scopes,objects,3,&context,10,100), "partial object table cannot be used");
	expect(!skp_path_scopes_inode_hidden(&config,&scopes,NULL,4,&context,10,100), "missing objects refused");
	expect(!skp_path_scopes_dirent_hidden_n(&config,&scopes,objects,4,&context,100,"aa",2), "dirent name length stays exact");
	expect(!skp_path_scopes_dirent_hidden_n(&config,&scopes,objects,4,&context,100,"a",0), "empty names refused");
	{ char unterminated[SKP_GROUP_PATH_LEN]; memset(unterminated,'a',sizeof(unterminated)); expect(!skp_path_scopes_dirent_hidden(&config,&scopes,objects,4,&context,100,unterminated), "normal wrapper requires bounded NUL termination"); }
	scopes.path_count = 3; expect(!skp_path_scopes_inode_hidden(&config,&scopes,objects,4,&context,10,100), "scope/object publication mismatch fails open");
}
static void other_family_tests(void)
{
	static struct skp_full_objects_config full, original;
	struct skp_group_object_key kstat = {0}, map = {0};
	struct skp_group_redirect_object redirect = {0};
	struct skp_group_mount_object mount = {0};
	struct skp_kstat_values values;
	struct skp_mount_query_result result;
	struct skp_subject_context context = caller(0);
	fixture(); memset(&full,0,sizeof(full)); full.version = 1; full.objects.version = 1; full.objects.paths = config;
	full.objects.kstat_count = full.objects.map_count = full.redirect_count = full.mount_count = 1;
	strcpy(full.objects.kstats[0].path,"/owned/stat"); full.objects.kstats[0].values.flags = 1; full.objects.kstats[0].values.ino = 9001;
	strcpy(full.objects.maps[0].path,"/owned/map"); strcpy(full.redirects[0].source,"/owned/source"); strcpy(full.redirects[0].target,"/owned/target"); strcpy(full.mounts[0].path,"/owned/mount");
	kstat.dev = map.dev = 10; kstat.ino = map.ino = 100;
	redirect.source.dev = redirect.target.dev = 10; redirect.source.ino = 100; redirect.target.ino = 200;
	redirect.source_mnt_id = 10; redirect.target_mnt_id = 20;
	mount.chain_count = 2; mount.cookies[0] = 1010; mount.ids[0] = 10; mount.cookies[1] = 1001; mount.ids[1] = 1;
	expect(!skp_full_objects_validate(&full), "other-family canonical fixture valid"); original = full;
	custom(0,SKP_SUBJECT_WHITELIST,0);
	expect(skp_path_scopes_inode_hidden(&full.objects.paths,&scopes,objects,4,&context,10,100), "custom root scope enables only its path");
	expect(!skp_group_objects_kstat_lookup(&full.objects,&kstat,&context,10,100,&values), "path override does not override kstat root exemption");
	expect(!skp_group_objects_map_hidden(&full.objects,&map,&context,10,100), "path override does not override mapping root exemption");
	expect(skp_full_redirect_find(&full,&redirect,&context,10,100,0,10,SKP_REDIRECT_FORWARD) == -1, "path override does not override redirect root exemption");
	skp_full_mount_lookup(&full,&mount,&context,1010,10,1,&result);
	expect(!result.hidden && !result.shown_id, "path override does not override mount root exemption");
	expect(!memcmp(&full,&original,sizeof(full)), "scope queries do not mutate canonical facts or other four families");
}
int main(void)
{
	validation_tests(); independent_scope_tests(); overlap_and_parity_tests(); other_family_tests();
	printf("PATH_SCOPES_HOST checks=%u passed=true kernel_calls=false production_source=true\n", checks);
	return 0;
}
