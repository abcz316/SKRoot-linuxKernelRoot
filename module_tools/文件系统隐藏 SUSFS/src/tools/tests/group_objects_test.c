// SPDX-License-Identifier: GPL-2.0-only
/* Pure immutable-object contract tests. No device, identity impersonation or
 * kernel interception. Link the actual production subject/path/object cores. */
#include "../../kernel/skp_group_objects.h"
#include "../../kernel/skp_policy_adapter.h"
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct skp_kstat_values) == 88, "payload wire size");
_Static_assert(sizeof(struct skp_group_kstat_rule) == 352, "kstat rule size");
_Static_assert(sizeof(struct skp_group_objects_config) == 71384, "complete config size");
_Static_assert(sizeof(struct skp_group_objects_message) == 71416, "complete frame size");
_Static_assert(offsetof(struct skp_group_objects_config, version) == 43208, "object header offset");
_Static_assert(offsetof(struct skp_group_objects_config, kstats) == 43224, "kstat table offset");
_Static_assert(offsetof(struct skp_group_objects_config, maps) == 54488, "map table offset");

static unsigned int checks;

static void expect(int condition, const char *name)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL check %u: %s\n", checks, name);
		exit(1);
	}
}

static struct skp_group_objects_config config_new(void)
{
	struct skp_group_objects_config c;

	memset(&c, 0, sizeof(c));
	c.version = SKP_GROUP_OBJECTS_VERSION;
	c.paths.version = SKP_GROUP_PATHS_VERSION;
	c.paths.subjects.version = SKP_SUBJECT_POLICY_VERSION;
	c.paths.subjects.facts_generation = 0x100000009ULL;
	c.paths.subjects.profile_count = 4;
	c.paths.subjects.profiles[1] = 7;
	c.paths.subjects.profiles[2] = 19;
	c.paths.subjects.profiles[3] = 27;
	c.paths.subjects.binding_count = 3;
	c.paths.subjects.bindings[0].uid = 10101;
	c.paths.subjects.bindings[0].profile_id = 7;
	c.paths.subjects.bindings[1].uid = 10102;
	c.paths.subjects.bindings[1].profile_id = 19;
	c.paths.subjects.bindings[2].uid = 10103;
	c.paths.subjects.bindings[2].profile_id = 27;
	return c;
}

static struct skp_subject_context caller(skp_subject_u32 uid)
{
	struct skp_subject_context c;

	memset(&c, 0, sizeof(c));
	c.actual_uid = uid;
	return c;
}

static void add(struct skp_group_objects_config *c,
		struct skp_group_object_key *ks, struct skp_group_object_key *maps,
		skp_subject_u32 profile, const char *path, skp_subject_u64 dev,
		skp_subject_u64 ino, skp_subject_u64 spoof)
{
	skp_subject_u32 k = c->kstat_count++, m = c->map_count++;

	expect(k < SKP_GROUP_KSTATS_MAX && m < SKP_GROUP_MAPS_MAX, "fixture capacities");
	c->kstats[k].profile_id = c->maps[m].profile_id = profile;
	strcpy(c->kstats[k].path, path);
	strcpy(c->maps[m].path, path);
	c->kstats[k].values.flags = 1;
	c->kstats[k].values.ino = spoof;
	ks[k].profile_id = maps[m].profile_id = profile;
	ks[k].dev = maps[m].dev = dev;
	ks[k].ino = maps[m].ino = ino;
}

static void verdict(const struct skp_group_objects_config *c,
		const struct skp_group_object_key *ks, const struct skp_group_object_key *maps,
		const struct skp_subject_context *context, skp_subject_u64 dev,
		skp_subject_u64 ino, int matched, skp_subject_u64 spoof)
{
	struct skp_kstat_values out;
	struct skp_kstat_values empty;

	memset(&out, 0xa5, sizeof(out));
	memset(&empty, 0, sizeof(empty));
	expect(skp_group_objects_kstat_lookup(c, ks, context, dev, ino, &out) == matched,
	       "kstat match verdict");
	expect(skp_group_objects_map_hidden(c, maps, context, dev, ino) == matched,
	       "map match verdict");
	if (matched)
		expect(out.flags == 1 && out.ino == spoof, "profile-specific copied payload");
	else
		expect(!memcmp(&out, &empty, sizeof(out)), "miss clears stale output");
}

static void test_subjects(void)
{
	struct skp_group_objects_config c = config_new(), old;
	struct skp_group_object_key ks[32] = {{0}}, maps[64] = {{0}};
	struct skp_subject_context a = caller(10101), b = caller(10102), empty = caller(10103);
	struct skp_subject_context ordinary = caller(10404), worker = caller(99001);
	struct skp_kstat_values result;

	add(&c, ks, maps, 7, "/fixtures/a", 12, 88, 111);
	add(&c, ks, maps, 19, "/fixtures/b", 12, 88, 222);
	add(&c, ks, maps, 0, "/fixtures/default", 12, 77, 333);
	expect(!skp_group_objects_keys_validate(&c, ks, maps), "same real inode cross-profile allowed");
	verdict(&c, ks, maps, &a, 12, 88, 1, 111);
	verdict(&c, ks, maps, &b, 12, 88, 1, 222);
	verdict(&c, ks, maps, &ordinary, 12, 77, 1, 333);
	verdict(&c, ks, maps, &ordinary, 12, 88, 0, 0);
	verdict(&c, ks, maps, &a, 12, 77, 0, 0);
	verdict(&c, ks, maps, &empty, 12, 88, 0, 0);
	verdict(&c, ks, maps, &empty, 12, 77, 0, 0);
	verdict(&c, ks, maps, &a, 13, 88, 0, 0);
	verdict(&c, ks, maps, &a, 12, 89, 0, 0);
	verdict(&c, ks, maps, &a, 0, 88, 0, 0);
	ks[0].dev = maps[0].dev = 0;
	verdict(&c, ks, maps, &a, 0, 88, 1, 111);
	verdict(&c, ks, maps, &a, 12, 88, 0, 0); /* raw zero is exact, never a wildcard */
	ks[0].dev = maps[0].dev = 12;
	expect(skp_group_objects_kstat_lookup(&c, ks, &a, 12, 88, &result), "copy succeeds");
	result.ino = 999;
	verdict(&c, ks, maps, &a, 12, 88, 1, 111);

	c.paths.subjects.whitelist_count = 1;
	c.paths.subjects.whitelist[0] = 10101;
	verdict(&c, ks, maps, &a, 12, 88, 0, 0);
	c.paths.subjects.mode = SKP_SUBJECT_BLACKLIST;
	c.paths.subjects.flags = SKP_SUBJECT_EXEMPT_ALL;
	verdict(&c, ks, maps, &a, 12, 88, 0, 0);
	c.paths.subjects.blacklist_count = 1;
	c.paths.subjects.blacklist[0] = 10101;
	verdict(&c, ks, maps, &a, 12, 88, 1, 111);
	a.precise_manager = 1;
	verdict(&c, ks, maps, &a, 12, 88, 0, 0);
	a.precise_manager = 0;
	c.paths.subjects.mode = SKP_SUBJECT_WHITELIST;
	c.paths.subjects.whitelist_count = c.paths.subjects.whitelist[0] = 0;
	c.paths.subjects.system_app_count = 1;
	c.paths.subjects.system_apps[0] = 10101;
	verdict(&c, ks, maps, &a, 12, 88, 0, 0);
	c.paths.subjects.flags = 0;
	verdict(&c, ks, maps, &a, 12, 88, 1, 111);
	ordinary.actual_uid = 0;
	c.paths.subjects.flags = SKP_SUBJECT_EXEMPT_ROOT;
	verdict(&c, ks, maps, &ordinary, 12, 77, 0, 0);
	c.paths.subjects.flags = 0;
	verdict(&c, ks, maps, &ordinary, 12, 77, 1, 333);
	ordinary.actual_uid = 2000;
	c.paths.subjects.flags = SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES;
	verdict(&c, ks, maps, &ordinary, 12, 77, 0, 0);
	c.paths.subjects.flags = 0;
	worker.worker_verified = 1;
	worker.origin_uid = 10101;
	worker.origin_facts_generation = c.paths.subjects.facts_generation;
	verdict(&c, ks, maps, &worker, 12, 88, 1, 111);
	old = c;
	++c.paths.subjects.facts_generation;
	verdict(&c, ks, maps, &worker, 12, 88, 0, 0);
	verdict(&old, ks, maps, &worker, 12, 88, 1, 111);
	worker.origin_facts_generation = c.paths.subjects.facts_generation;
	verdict(&c, ks, maps, &worker, 12, 88, 1, 111);
	worker.worker_verified = 0;
	verdict(&c, ks, maps, &worker, 12, 88, 0, 0);
	ordinary.actual_uid = 110101;
	verdict(&c, ks, maps, &ordinary, 12, 88, 0, 0);
}

static void test_validation(void)
{
	static const char *bad_paths[] = { "", "/", "relative", "//x", "/a/", "/a//b",
		"/a/.", "/a/..", "/a/./b", "/a/../b", "/a\nb", "/a\177b" };
	struct skp_group_objects_config c = config_new(), base;
	struct skp_group_object_key ks[32] = {{0}}, maps[64] = {{0}};
	unsigned int i, family;
	unsigned char *bytes;

	expect(skp_group_objects_validate(NULL) == SKP_GROUP_PATHS_ERR_ARGUMENT, "null config");
	expect(!skp_group_objects_validate(&c), "complete empty config valid");
	expect(!skp_group_objects_keys_validate(&c, NULL, NULL), "empty keys can be null");
	add(&c, ks, maps, 7, "/fixtures/a", 0, 1, 3);
	base = c;
#define BAD(field, value, error) do { c = base; c.field = (value); \
	expect(skp_group_objects_validate(&c) == (error), #field); } while (0)
	BAD(version, 0, SKP_GROUP_PATHS_ERR_VERSION);
	BAD(reserved, 1, SKP_GROUP_PATHS_ERR_HEADER);
	BAD(kstat_count, 33, SKP_GROUP_PATHS_ERR_COUNT);
	BAD(map_count, 65, SKP_GROUP_PATHS_ERR_COUNT);
	BAD(paths.version, 0, SKP_GROUP_PATHS_ERR_VERSION);
	BAD(paths.subjects.facts_generation, 0, SKP_SUBJECT_ERR_HEADER);
	BAD(kstats[0].profile_id, 123, SKP_GROUP_PATHS_ERR_PROFILE);
	BAD(maps[0].profile_id, 123, SKP_GROUP_PATHS_ERR_PROFILE);
	BAD(kstats[0].reserved, 1, SKP_GROUP_PATHS_ERR_HEADER);
	BAD(maps[0].flags, 1, SKP_GROUP_PATHS_ERR_HEADER);
	BAD(kstats[0].values.flags, 0, SKP_GROUP_PATHS_ERR_HEADER);
	BAD(kstats[0].values.flags, 4096, SKP_GROUP_PATHS_ERR_HEADER);
	BAD(kstats[0].values.reserved, 1, SKP_GROUP_PATHS_ERR_HEADER);
#undef BAD
	for (family = 0; family < 2; ++family) {
		for (i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); ++i) {
			c = base;
			strcpy(family ? c.maps[0].path : c.kstats[0].path, bad_paths[i]);
			/* Ensure the invalid path's own termination is canonical padding. */
			memset((family ? c.maps[0].path : c.kstats[0].path) + strlen(bad_paths[i]),
			       0, 256 - strlen(bad_paths[i]));
			expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_PATH, "bad lexical path");
		}
		c = base;
		memset(family ? c.maps[0].path : c.kstats[0].path, 'a', 256);
		expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_PATH, "unterminated path");
		c = base;
		(family ? c.maps[0].path : c.kstats[0].path)[255] = 'X';
		expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_PATH, "path nonzero tail");
		c = base;
		if (family) { c.maps[1] = c.maps[0]; c.map_count = 2; }
		else { c.kstats[1] = c.kstats[0]; c.kstat_count = 2; }
		expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_DUPLICATE, "same-profile duplicate");
		if (family) c.maps[1].profile_id = 19;
		else c.kstats[1].profile_id = 19;
		expect(!skp_group_objects_validate(&c), "cross-profile same path allowed");
		for (i = 0; i < (family ? sizeof(c.maps[1]) : sizeof(c.kstats[1])); ++i) {
			c = base;
			bytes = family ? (unsigned char *)&c.maps[1] : (unsigned char *)&c.kstats[1];
			bytes[i] = 1;
			expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_TAIL, "unused slot tail byte");
		}
	}
	c = base;
	c.paths.path_count = 1;
	c.paths.rules[0] = c.maps[0];
	expect(!skp_group_objects_validate(&c), "same path may occur across all families");
	expect(!skp_group_objects_keys_validate(&base, ks, maps), "raw device zero valid exact key");
	expect(skp_group_objects_keys_validate(&base, NULL, maps) == SKP_GROUP_PATHS_ERR_ARGUMENT,
	       "missing kstat keys rejected");
	expect(skp_group_objects_keys_validate(&base, ks, NULL) == SKP_GROUP_PATHS_ERR_ARGUMENT,
	       "missing map keys rejected");
	for (family = 0; family < 2; ++family) {
		struct skp_group_object_key *keys = family ? maps : ks;
		keys[0].reserved = 1;
		expect(skp_group_objects_keys_validate(&base, ks, maps) == SKP_GROUP_PATHS_ERR_OBJECT, "key reserved");
		keys[0].reserved = 0;
		keys[0].profile_id = 19;
		expect(skp_group_objects_keys_validate(&base, ks, maps) == SKP_GROUP_PATHS_ERR_OBJECT, "key profile mismatch");
		keys[0].profile_id = 7;
		keys[0].ino = 0;
		expect(skp_group_objects_keys_validate(&base, ks, maps) == SKP_GROUP_PATHS_ERR_OBJECT, "key inode zero");
		keys[0].ino = 1;
		c = base;
		if (family) { c.maps[1] = c.maps[0]; strcpy(c.maps[1].path, "/fixtures/b"); c.map_count = 2; }
		else { c.kstats[1] = c.kstats[0]; strcpy(c.kstats[1].path, "/fixtures/b"); c.kstat_count = 2; }
		keys[1] = keys[0];
		expect(skp_group_objects_keys_validate(&c, ks, maps) == SKP_GROUP_PATHS_ERR_ALIAS, "same-profile aliases rejected");
		if (family) c.maps[1].profile_id = 19;
		else c.kstats[1].profile_id = 19;
		keys[1].profile_id = 19;
		expect(!skp_group_objects_keys_validate(&c, ks, maps), "cross-profile aliases permitted");
		keys[1].profile_id = 7;
		if (family) c.maps[1].profile_id = 7;
		else c.kstats[1].profile_id = 7;
		keys[1].dev++;
		expect(!skp_group_objects_keys_validate(&c, ks, maps), "same inode different device distinct");
	}
}

static void test_values(void)
{
	struct skp_group_objects_config c = config_new(), base;
	struct skp_group_object_key ks[32] = {{0}}, maps[64] = {{0}};
	struct skp_kstat_values *v = &c.kstats[0].values;
	const size_t offsets[] = { offsetof(struct skp_kstat_values, ino),
		offsetof(struct skp_kstat_values, dev_encoded), offsetof(struct skp_kstat_values, nlink),
		offsetof(struct skp_kstat_values, size), offsetof(struct skp_kstat_values, atime_sec),
		offsetof(struct skp_kstat_values, atime_nsec), offsetof(struct skp_kstat_values, mtime_sec),
		offsetof(struct skp_kstat_values, mtime_nsec), offsetof(struct skp_kstat_values, ctime_sec),
		offsetof(struct skp_kstat_values, ctime_nsec), offsetof(struct skp_kstat_values, blocks),
		offsetof(struct skp_kstat_values, blksize) };
	unsigned int bit;

	add(&c, ks, maps, 7, "/fixtures/a", 12, 88, 0);
	base = c;
	for (bit = 0; bit < 12; ++bit) {
		c = base;
		v->flags = 1U << bit;
		if (bit == 11) v->blksize = 1;
		expect(!skp_group_objects_validate(&c), "each individual mask bit accepted incl zero values");
		c = base;
		v->flags = bit ? 1 : 4;
		((unsigned char *)v)[offsets[bit]] = 1;
		expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_HEADER, "unselected payload must be zero");
	}
	c = base;
	v->flags = 4095;
	v->ino = ~(skp_subject_u64)0;
	v->dev_encoded = 0xffffffffU;
	v->nlink = 0xffffffffU;
	v->size = v->blocks = LLONG_MAX;
	v->atime_sec = v->ctime_sec = LLONG_MIN;
	v->mtime_sec = LLONG_MAX;
	v->atime_nsec = v->mtime_nsec = v->ctime_nsec = 999999999U;
	v->blksize = INT_MAX;
	expect(!skp_group_objects_validate(&c), "all common maximums and signed times accepted");
	base = c;
#define BAD_VALUE(field, value) do { c = base; v->field = (value); \
	expect(skp_group_objects_validate(&c) == SKP_GROUP_PATHS_ERR_HEADER, #field " range"); } while (0)
	BAD_VALUE(dev_encoded, 0x100000000ULL);
	BAD_VALUE(size, -1);
	BAD_VALUE(blocks, -1);
	BAD_VALUE(blksize, 0);
	BAD_VALUE(blksize, -1);
	BAD_VALUE(blksize, 2147483648LL);
	BAD_VALUE(atime_nsec, 1000000000U);
	BAD_VALUE(mtime_nsec, 1000000000U);
	BAD_VALUE(ctime_nsec, 1000000000U);
#undef BAD_VALUE
}

static void test_max_and_defensive(void)
{
	struct skp_group_objects_config c = config_new(), base;
	struct skp_group_object_key ks[32] = {{0}}, maps[64] = {{0}};
	struct skp_subject_context context = caller(10101);
	unsigned int i;

	for (i = 0; i < 32; ++i) {
		char path[64];
		(void)snprintf(path, sizeof(path), "/fixtures/object-%u", i);
		add(&c, ks, maps, 7, path, 12, i + 1, i + 100);
	}
	for (; i < 64; ++i) {
		c.maps[i].profile_id = 7;
		(void)snprintf(c.maps[i].path, sizeof(c.maps[i].path), "/fixtures/map-%u", i);
		maps[i].profile_id = 7;
		maps[i].dev = 12;
		maps[i].ino = i + 1;
		c.map_count++;
	}
	expect(!skp_group_objects_keys_validate(&c, ks, maps), "full capacity resolves valid tables");
	for (i = 1; i <= 32; ++i)
		verdict(&c, ks, maps, &context, 12, i, 1, i + 99);
	expect(skp_group_objects_map_hidden(&c, maps, &context, 12, 64), "last map slot read");
	verdict(&c, ks, maps, &context, 12, 65, 0, 0);
	base = c;
#define MISS(field, value) do { c = base; c.field = (value); \
	verdict(&c, ks, maps, &context, 12, 1, 0, 0); } while (0)
	MISS(version, 0);
	MISS(reserved, 1);
	MISS(kstat_count, 33);
	MISS(map_count, 65);
	MISS(paths.version, 0);
	MISS(paths.reserved, 1);
	MISS(paths.path_count, 129);
#undef MISS
	verdict(NULL, ks, maps, &context, 12, 1, 0, 0);
	verdict(&base, NULL, NULL, &context, 12, 1, 0, 0);
	verdict(&base, ks, maps, NULL, 12, 1, 0, 0);
	verdict(&base, ks, maps, &context, 12, 0, 0, 0);
	expect(!skp_group_objects_kstat_lookup(&base, ks, &context, 12, 1, NULL), "null output safe");
	c = config_new();
	verdict(&c, NULL, NULL, &context, 12, 1, 0, 0);
}

int main(void)
{
	test_subjects();
	test_validation();
	test_values();
	test_max_and_defensive();
	printf("{\"test\":\"group_objects\",\"checks\":%u,\"passed\":true,"
	       "\"kernel_execution\":false,\"device_execution\":false}\n", checks);
	return 0;
}
