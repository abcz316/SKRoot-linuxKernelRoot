// SPDX-License-Identifier: GPL-2.0-only
/* Pure host contract tests: no syscalls, identity impersonation or interception.
 * cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 kernel/skp_subject_policy.c
 *    kernel/skp_group_paths.c tools/tests/group_paths_test.c -o /tmp/group_paths
 */
#include "../../kernel/skp_group_paths.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct skp_group_path_rule) == 264, "fixed rule layout");
_Static_assert(sizeof(struct skp_group_paths_config) == 43208, "fixed config layout");
_Static_assert(offsetof(struct skp_group_paths_config, version) == 9400,
	       "version follows full subject snapshot");
_Static_assert(offsetof(struct skp_group_paths_config, rules) == 9416,
	       "fixed rule table offset");
_Static_assert(sizeof(struct skp_group_path_object) == 280, "internal object layout");

static unsigned int checks;

static void expect(int condition, const char *name)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL: %s (check %u)\n", name, checks);
		exit(1);
	}
}

static struct skp_group_paths_config empty_config(void)
{
	struct skp_group_paths_config config;

	memset(&config, 0, sizeof(config));
	config.version = SKP_GROUP_PATHS_VERSION;
	config.subjects.version = SKP_SUBJECT_POLICY_VERSION;
	config.subjects.profile_count = 4;
	config.subjects.profiles[1] = 7;
	config.subjects.profiles[2] = 19;
	config.subjects.profiles[3] = 27;
	config.subjects.facts_generation = 0x100000009ULL;
	config.subjects.binding_count = 3;
	config.subjects.bindings[0].uid = 10101;
	config.subjects.bindings[0].profile_id = 7;
	config.subjects.bindings[1].uid = 10102;
	config.subjects.bindings[1].profile_id = 19;
	config.subjects.bindings[2].uid = 10103;
	config.subjects.bindings[2].profile_id = 27;
	return config;
}

static struct skp_subject_context caller(skp_subject_u32 uid)
{
	struct skp_subject_context context;

	memset(&context, 0, sizeof(context));
	context.actual_uid = uid;
	return context;
}

static void add_rule(struct skp_group_paths_config *config,
		     struct skp_group_path_object *objects,
		     skp_subject_u32 profile, const char *path,
		     skp_subject_u64 dev, skp_subject_u64 ino, const char *name)
{
	skp_subject_u32 index = config->path_count++;

	expect(index < SKP_GROUP_PATHS_MAX, "test fixture stays in capacity");
	config->rules[index].profile_id = profile;
	strcpy(config->rules[index].path, path);
	memset(&objects[index], 0, sizeof(objects[index]));
	objects[index].profile_id = profile;
	objects[index].dev = dev;
	objects[index].ino = ino;
	strcpy(objects[index].name, name);
}

static void expect_hidden(const struct skp_group_paths_config *config,
		const struct skp_group_path_object *objects,
		const struct skp_subject_context *context,
		skp_subject_u64 dev, skp_subject_u64 ino, const char *name,
		int hidden, const char *label)
{
	expect(skp_group_paths_inode_hidden(config, objects, config->path_count,
			context, dev, ino) == hidden, label);
	expect(skp_group_paths_dirent_hidden(config, objects, config->path_count,
			context, ino, name) == hidden, label);
}

static void test_group_visibility(void)
{
	struct skp_group_paths_config config = empty_config();
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
	struct skp_subject_context group_a = caller(10101), group_b = caller(10102);
	struct skp_subject_context no_rules = caller(10103), ordinary = caller(10404);
	const char raw_name[] = { 'a', '.', 't', 'x', 't', 'X' };

	memset(objects, 0, sizeof(objects));
	add_rule(&config, objects, 0, "/fixtures/default.txt", 10, 100, "default.txt");
	add_rule(&config, objects, 7, "/fixtures/a.txt", 10, 200, "a.txt");
	add_rule(&config, objects, 19, "/fixtures/b.txt", 10, 300, "b.txt");
	expect(skp_group_paths_objects_validate(&config, objects, 3) == 0,
	       "three-profile fixture is a complete valid publication");
	expect_hidden(&config, objects, &group_a, 10, 200, "a.txt", 1, "A hides its target");
	expect_hidden(&config, objects, &group_b, 10, 200, "a.txt", 0, "B sees same inode hidden from A");
	expect_hidden(&config, objects, &group_a, 10, 300, "b.txt", 0, "A sees B target");
	expect_hidden(&config, objects, &group_b, 10, 300, "b.txt", 1, "B hides its target");
	expect_hidden(&config, objects, &ordinary, 10, 100, "default.txt", 1, "unbound UID uses default");
	expect_hidden(&config, objects, &group_a, 10, 100, "default.txt", 0, "default does not leak into A");
	expect_hidden(&config, objects, &no_rules, 10, 100, "default.txt", 0, "empty group does not inherit default");
	expect_hidden(&config, objects, &no_rules, 10, 200, "a.txt", 0, "empty group remains visible");
	expect(skp_group_paths_inode_hidden(&config, objects, 3, &group_a, 11, 200) == 0,
	       "inode check distinguishes device");
	expect(skp_group_paths_dirent_hidden(&config, objects, 3, &group_a, 200, "other") == 0,
	       "dirent check requires basename");
	expect(skp_group_paths_dirent_hidden(&config, objects, 3, &group_a, 201, "a.txt") == 0,
	       "dirent check requires inode");
	expect(skp_group_paths_dirent_hidden_n(&config, objects, 3, &group_a,
	       200, raw_name, 5) == 1, "actor buffer need not be NUL terminated");
	expect(skp_group_paths_dirent_hidden_n(&config, objects, 3, &group_a,
	       200, raw_name, sizeof(raw_name)) == 0, "actor length is authoritative");

	/* Two profiles may intentionally hide the same real inode. Publishing one
	 * group's rule does not rely on mutating a shared upstream object record. */
	add_rule(&config, objects, 19, "/fixtures/alias-to-a", 10, 200, "a.txt");
	expect(skp_group_paths_objects_validate(&config, objects, 4) == 0,
	       "cross-profile same inode allowed");
	expect_hidden(&config, objects, &group_b, 10, 200, "a.txt", 1, "B now hides shared inode independently");
	expect_hidden(&config, objects, &group_a, 10, 200, "a.txt", 1, "A retains shared inode");
	expect_hidden(&config, objects, &ordinary, 10, 200, "a.txt", 0, "shared inode does not leak into default");

	/* Following a symlink resolves to the target dentry, not the lexical name. */
	strcpy(objects[3].name, "resolved.txt");
	expect(skp_group_paths_objects_validate(&config, objects, 4) == 0,
	       "resolved basename may differ from configured alias");
	expect(skp_group_paths_dirent_hidden(&config, objects, 4, &group_b,
	       200, "alias-to-a") == 0, "lexical alias is not invented as resolved basename");
	expect(skp_group_paths_dirent_hidden(&config, objects, 4, &group_b,
	       200, "resolved.txt") == 1, "resolved dentry basename controls dirent matching");
}

static void test_subject_contract(void)
{
	struct skp_group_paths_config config = empty_config();
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
	struct skp_subject_context context = caller(10101);
	struct skp_group_paths_config old;

	memset(objects, 0, sizeof(objects));
	add_rule(&config, objects, 7, "/fixtures/private", 20, 400, "private");
	config.subjects.whitelist_count = 1;
	config.subjects.whitelist[0] = 10101;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "whitelist precedes group");
	config.subjects.mode = SKP_SUBJECT_BLACKLIST;
	config.subjects.flags = SKP_SUBJECT_EXEMPT_ALL;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "not blacklisted remains visible");
	config.subjects.blacklist_count = 1;
	config.subjects.blacklist[0] = 10101;
	expect_hidden(&config, objects, &context, 20, 400, "private", 1, "blacklist overrides whitelist and broad exemptions");
	context.precise_manager = 1;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "exact manager remains exempt in blacklist mode");
	context.precise_manager = 0;
	config.subjects.mode = SKP_SUBJECT_WHITELIST;
	config.subjects.whitelist_count = 0;
	config.subjects.whitelist[0] = 0;
	config.subjects.system_app_count = 1;
	config.subjects.system_apps[0] = 10101;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "system app exemption uses declared package facts");
	config.subjects.flags = 0;
	expect_hidden(&config, objects, &context, 20, 400, "private", 1, "system-app flag can be disabled");

	context.actual_uid = 0;
	context.worker_verified = 1;
	context.origin_uid = 10101;
	context.origin_facts_generation = config.subjects.facts_generation;
	expect_hidden(&config, objects, &context, 20, 400, "private", 1, "current verified worker inherits origin group");
	config.subjects.flags = SKP_SUBJECT_EXEMPT_ROOT;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "root exemption uses actual credentials");
	config.subjects.flags = 0;
	context.actual_uid = 2000;
	config.subjects.flags = SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "system-process exemption uses actual credentials");
	config.subjects.flags = 0;
	context.actual_uid = 99001;
	old = config;
	++config.subjects.facts_generation;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "old worker facts cannot cross a publication");
	expect_hidden(&old, objects, &context, 20, 400, "private", 1, "held old snapshot uses its own matching facts");
	context.origin_facts_generation = config.subjects.facts_generation;
	expect_hidden(&config, objects, &context, 20, 400, "private", 1, "reverified new-generation worker is grouped");
	context.worker_verified = 0;
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "unverified origin cannot borrow group");
	context = caller(110101);
	expect_hidden(&config, objects, &context, 20, 400, "private", 0, "full multiuser UID is not modulo mapped");

	config.subjects.binding_count = 2;
	config.subjects.bindings[1].uid = 10101;
	config.subjects.bindings[1].profile_id = 19;
	memset(&config.subjects.bindings[2], 0, sizeof(config.subjects.bindings[2]));
	expect(skp_group_paths_validate(&config) == SKP_SUBJECT_ERR_BINDING_CONFLICT,
	       "shared UID cannot be split into two groups");
}

static void test_config_validation(void)
{
	static const char *bad_paths[] = {
		"", "/", "relative", "//root", "/a//b", "/a/", "/a/.", "/a/..",
		"/a/./b", "/a/../b", "/./a", "/../a"
	};
	static const char *good_paths[] = {
		"/a", "/a.b", "/..suffix/.prefix", "/fixtures/\xe4\xb8\xad\xe6\x96\x87 \xe8\x84\x9a\xe6\x9c\xac.sh"
	};
	struct skp_group_paths_config config = empty_config(), base;
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
	unsigned int i;

	memset(objects, 0, sizeof(objects));
	expect(skp_group_paths_validate(NULL) == SKP_GROUP_PATHS_ERR_ARGUMENT, "null config rejected");
	expect(skp_group_paths_validate(&config) == 0, "empty config valid");
	expect(skp_group_paths_objects_validate(&config, NULL, 0) == 0, "empty publication needs no object array");
	add_rule(&config, objects, 7, "/fixtures/a", 0, 1, "a");
	base = config;
	config.version++;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_VERSION, "version rejected");
	config = base;
	config.reserved = 1;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_HEADER, "reserved config rejected");
	config = base;
	config.path_count = SKP_GROUP_PATHS_MAX + 1;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_COUNT, "oversized count rejected before scan");
	config = base;
	config.rules[0].flags = 1;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_HEADER, "future flags rejected");
	config = base;
	config.rules[0].profile_id = 8;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PROFILE, "undeclared group rejected");
	config = base;
	config.subjects.reserved[0] = 1;
	expect(skp_group_paths_validate(&config) == SKP_SUBJECT_ERR_HEADER, "full subject validation propagated");
	for (i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); ++i) {
		config = base;
		memset(config.rules[0].path, 0, SKP_GROUP_PATH_LEN);
		strcpy(config.rules[0].path, bad_paths[i]);
		expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PATH, "ambiguous path rejected");
	}
	for (i = 0; i < sizeof(good_paths) / sizeof(good_paths[0]); ++i) {
		config = base;
		memset(config.rules[0].path, 0, SKP_GROUP_PATH_LEN);
		strcpy(config.rules[0].path, good_paths[i]);
		expect(skp_group_paths_validate(&config) == 0, "unambiguous international path accepted");
	}
	for (i = 1; i < 0x20; ++i) {
		config = base;
		config.rules[0].path[2] = (char)i;
		expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PATH, "ASCII control rejected");
	}
	config = base;
	config.rules[0].path[2] = 0x7f;
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PATH, "DEL rejected");
	config = base;
	memset(config.rules[0].path, 'x', SKP_GROUP_PATH_LEN);
	config.rules[0].path[0] = '/';
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PATH, "unterminated path rejected");
	config.rules[0].path[SKP_GROUP_PATH_LEN - 1] = 0;
	expect(skp_group_paths_validate(&config) == 0, "255-byte path supported");
	config = base;
	config.rules[0].path[SKP_GROUP_PATH_LEN - 1] = 'x';
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_PATH, "hidden bytes after NUL rejected");
	for (i = 0; i < sizeof(config.rules[1]); ++i) {
		config = base;
		((unsigned char *)&config.rules[1])[i] = 1;
		expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_TAIL, "every unused rule byte must be zero");
	}
	config = base;
	add_rule(&config, objects, 7, "/fixtures/a", 1, 2, "a");
	expect(skp_group_paths_validate(&config) == SKP_GROUP_PATHS_ERR_DUPLICATE, "same-profile duplicate path rejected");
	config.rules[1].profile_id = 19;
	objects[1].profile_id = 19;
	expect(skp_group_paths_validate(&config) == 0, "same lexical path in another profile accepted");
}

static void test_objects_validation(void)
{
	struct skp_group_paths_config config = empty_config();
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX], saved;
	unsigned int i;

	memset(objects, 0, sizeof(objects));
	add_rule(&config, objects, 7, "/fixtures/link", 0, 1, "target");
	saved = objects[0];
	expect(skp_group_paths_objects_validate(&config, objects, 1) == 0, "resolved target and zero device accepted");
	expect(skp_group_paths_objects_validate(&config, NULL, 1) == SKP_GROUP_PATHS_ERR_ARGUMENT, "missing resolved array rejected");
	expect(skp_group_paths_objects_validate(&config, objects, 0) == SKP_GROUP_PATHS_ERR_COUNT, "unresolved target cannot publish");
	expect(skp_group_paths_objects_validate(&config, objects, SKP_GROUP_PATHS_MAX + 1) == SKP_GROUP_PATHS_ERR_COUNT,
	       "object count overflow rejected");
	objects[0].profile_id = 19;
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "object profile must match rule ordinal");
	objects[0] = saved;
	objects[0].reserved = 1;
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "object reserved field rejected");
	objects[0] = saved;
	objects[0].ino = 0;
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "zero inode rejected");
	objects[0] = saved;
	memset(objects[0].name, 0, SKP_GROUP_PATH_LEN);
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "empty basename rejected");
	objects[0] = saved;
	strcpy(objects[0].name, "a/b");
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "basename slash rejected");
	objects[0] = saved;
	memset(objects[0].name, 0, SKP_GROUP_PATH_LEN);
	strcpy(objects[0].name, ".");
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "dot basename rejected");
	strcpy(objects[0].name, "..");
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "dotdot basename rejected");
	objects[0] = saved;
	objects[0].name[SKP_GROUP_PATH_LEN - 1] = 'x';
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "basename trailing bytes rejected");
	memset(objects[0].name, 'x', SKP_GROUP_PATH_LEN);
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "unterminated basename rejected");
	objects[0].name[SKP_GROUP_PATH_LEN - 1] = 0;
	expect(skp_group_paths_objects_validate(&config, objects, 1) == 0, "255-byte resolved basename accepted");
	for (i = 1; i < 0x20; ++i) {
		objects[0] = saved;
		objects[0].name[0] = (char)i;
		expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "basename controls rejected");
	}
	objects[0] = saved;
	objects[0].name[0] = 0x7f;
	expect(skp_group_paths_objects_validate(&config, objects, 1) == SKP_GROUP_PATHS_ERR_OBJECT, "basename DEL rejected");
	objects[0] = saved;
	add_rule(&config, objects, 7, "/fixtures/another-link", 0, 1, "different");
	expect(skp_group_paths_objects_validate(&config, objects, 2) == SKP_GROUP_PATHS_ERR_ALIAS,
	       "same-profile hardlink or symlink alias rejected by dev and inode");
	objects[1].dev = 1;
	expect(skp_group_paths_objects_validate(&config, objects, 2) == 0, "same inode on another device is distinct");
	objects[1].dev = 0;
	config.rules[1].profile_id = 19;
	objects[1].profile_id = 19;
	expect(skp_group_paths_objects_validate(&config, objects, 2) == 0, "same real object may be shared across profiles");
}

static void test_capacity_and_defensive_headers(void)
{
	struct skp_group_paths_config config = empty_config();
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
	struct skp_subject_context context = caller(10101);
	char path[64], name[32], unterminated[SKP_GROUP_PATH_LEN];
	unsigned int i;

	memset(objects, 0, sizeof(objects));
	for (i = 0; i < SKP_GROUP_PATHS_MAX; ++i) {
		snprintf(path, sizeof(path), "/fixtures/file-%u", i);
		snprintf(name, sizeof(name), "file-%u", i);
		add_rule(&config, objects, 7, path, 99, 1000 + i, name);
	}
	expect(skp_group_paths_objects_validate(&config, objects, SKP_GROUP_PATHS_MAX) == 0,
	       "full 128-rule publication is valid");
	for (i = 0; i < SKP_GROUP_PATHS_MAX; ++i) {
		snprintf(name, sizeof(name), "file-%u", i);
		expect_hidden(&config, objects, &context, 99, 1000 + i, name, 1,
			      "every slot including final slot is searchable");
	}
	expect(skp_group_paths_inode_hidden(NULL, objects, 128, &context, 99, 1000) == 0,
	       "null hot-path snapshot suppresses interception");
	expect(skp_group_paths_inode_hidden(&config, NULL, 128, &context, 99, 1000) == 0,
	       "missing hot-path table suppresses interception");
	expect(skp_group_paths_inode_hidden(&config, objects, 127, &context, 99, 1000) == 0,
	       "mismatched config and object counts suppress interception");
	expect(skp_group_paths_inode_hidden(&config, objects, 129, &context, 99, 1000) == 0,
	       "oversized hot-path count suppresses interception");
	expect(skp_group_paths_inode_hidden(&config, objects, 128, NULL, 99, 1000) == 0,
	       "null context suppresses interception");
	expect(skp_group_paths_inode_hidden(&config, objects, 128, &context, 99, 0) == 0,
	       "zero inode never matches");
	expect(skp_group_paths_dirent_hidden(&config, objects, 128, &context, 1000, NULL) == 0,
	       "null actor name rejected");
	expect(skp_group_paths_dirent_hidden(&config, objects, 128, &context, 1000, "") == 0,
	       "empty actor name rejected");
	memset(unterminated, 'x', sizeof(unterminated));
	expect(skp_group_paths_dirent_hidden(&config, objects, 128, &context, 1000, unterminated) == 0,
	       "unterminated actor name bounded");
	expect(skp_group_paths_dirent_hidden_n(&config, objects, 128, &context, 1000, "file-0", 256) == 0,
	       "oversized actor name rejected before read");
	config.version++;
	expect(skp_group_paths_inode_hidden(&config, objects, 128, &context, 99, 1000) == 0,
	       "unknown hot-path version suppresses interception");
	config.version = SKP_GROUP_PATHS_VERSION;
	config.reserved = 1;
	expect(skp_group_paths_inode_hidden(&config, objects, 128, &context, 99, 1000) == 0,
	       "invalid hot-path header suppresses interception");
}

static void test_joint_maximum_subject_tables(void)
{
	struct skp_group_paths_config config = empty_config();
	struct skp_group_path_object objects[SKP_GROUP_PATHS_MAX];
	char path[64], name[32];
	unsigned int i;

	memset(objects, 0, sizeof(objects));
	config.subjects.profile_count = SKP_SUBJECT_MAX_PROFILES;
	for (i = 0; i < SKP_SUBJECT_MAX_PROFILES; ++i)
		config.subjects.profiles[i] = i;
	config.subjects.whitelist_count = SKP_SUBJECT_MAX_LIST_UIDS;
	config.subjects.blacklist_count = SKP_SUBJECT_MAX_LIST_UIDS;
	for (i = 0; i < SKP_SUBJECT_MAX_LIST_UIDS; ++i) {
		config.subjects.whitelist[i] = 20000 + i;
		config.subjects.blacklist[i] = 10000 + i;
	}
	config.subjects.system_app_count = SKP_SUBJECT_MAX_SYSTEM_UIDS;
	for (i = 0; i < SKP_SUBJECT_MAX_SYSTEM_UIDS; ++i)
		config.subjects.system_apps[i] = 10000 + i;
	config.subjects.binding_count = SKP_SUBJECT_MAX_BINDINGS;
	for (i = 0; i < SKP_SUBJECT_MAX_BINDINGS; ++i) {
		config.subjects.bindings[i].uid = 10000 + i;
		config.subjects.bindings[i].profile_id = i % SKP_SUBJECT_MAX_PROFILES;
	}
	for (i = 0; i < SKP_GROUP_PATHS_MAX; ++i) {
		snprintf(path, sizeof(path), "/fixtures/max-%u", i);
		snprintf(name, sizeof(name), "max-%u", i);
		add_rule(&config, objects, i % SKP_SUBJECT_MAX_PROFILES,
			 path, 10, 3000 + i, name);
	}
	expect(skp_group_paths_objects_validate(&config, objects, SKP_GROUP_PATHS_MAX) == 0,
	       "all subject tables and paths at maximum publish together");
	for (i = 0; i < SKP_GROUP_PATHS_MAX; ++i) {
		struct skp_subject_context owner = caller(10000 +
			(i % SKP_SUBJECT_MAX_PROFILES));
		struct skp_subject_context neighbor = caller(10000 +
			((i + 1) % SKP_SUBJECT_MAX_PROFILES));

		snprintf(name, sizeof(name), "max-%u", i);
		expect_hidden(&config, objects, &owner, 10, 3000 + i, name, 1,
			      "each maximum-table profile owns its target");
		expect_hidden(&config, objects, &neighbor, 10, 3000 + i, name, 0,
			      "neighbor maximum-table profile sees the same inode");
	}
}

int main(void)
{
	test_group_visibility();
	test_subject_contract();
	test_config_validation();
	test_objects_validation();
	test_capacity_and_defensive_headers();
	test_joint_maximum_subject_tables();
	printf("GROUP_PATHS_HOST checks=%u passed=true kernel_calls=false\n", checks);
	return 0;
}
