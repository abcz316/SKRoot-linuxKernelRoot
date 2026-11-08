// SPDX-License-Identifier: GPL-2.0-only
/* Production pure core, owned synthetic keys only; no kernel/device calls. */
#include "../../kernel/skp_full_objects.h"
#include "../../kernel/skp_policy_adapter.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct skp_policy_message) == 9432, "legacy frame");
_Static_assert(sizeof(struct skp_group_paths_message) == 43240, "path frame");
_Static_assert(sizeof(struct skp_group_objects_message) == 71416, "object frame");
_Static_assert(sizeof(struct skp_full_objects_message) == 121608, "full frame");
_Static_assert(offsetof(struct skp_full_objects_config, version) == 71384, "full header");
_Static_assert(offsetof(struct skp_full_objects_config, redirects) == 71400, "redirect offset");
_Static_assert(offsetof(struct skp_full_objects_config, mounts) == 104680, "mount offset");

static struct skp_full_objects_config config, saved;
static struct skp_group_redirect_object redirects[SKP_GROUP_REDIRECTS_MAX];
static struct skp_group_mount_object mounts[SKP_GROUP_MOUNTS_MAX];
static unsigned int checks;
static void expect(int condition, const char *name)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL check %u: %s\n", checks, name);
		exit(1);
	}
}
static void init(void)
{
	struct skp_subject_policy *s;
	memset(&config, 0, sizeof(config));
	memset(redirects, 0, sizeof(redirects));
	memset(mounts, 0, sizeof(mounts));
	config.version = SKP_FULL_OBJECTS_VERSION;
	config.objects.version = SKP_GROUP_OBJECTS_VERSION;
	config.objects.paths.version = SKP_GROUP_PATHS_VERSION;
	s = &config.objects.paths.subjects;
	s->version = SKP_SUBJECT_POLICY_VERSION;
	s->facts_generation = 17;
	s->profile_count = 4;
	s->profiles[1] = 7; s->profiles[2] = 19; s->profiles[3] = 27;
	s->binding_count = 3;
	s->bindings[0].uid = 10101; s->bindings[0].profile_id = 7;
	s->bindings[1].uid = 10102; s->bindings[1].profile_id = 19;
	s->bindings[2].uid = 10103; s->bindings[2].profile_id = 27;
}
static struct skp_subject_context caller(unsigned int uid)
{
	struct skp_subject_context c;
	memset(&c, 0, sizeof(c)); c.actual_uid = uid;
	return c;
}
static void redirect(unsigned int profile, const char *source, const char *target,
		unsigned long long dev, unsigned long long ino, unsigned long long destination)
{
	unsigned int i = config.redirect_count++;
	struct skp_group_redirect_object *o = &redirects[i];
	config.redirects[i].profile_id = o->profile_id = profile;
	strcpy(config.redirects[i].source, source); strcpy(config.redirects[i].target, target);
	o->source.dev = o->target.dev = dev;
	o->source.ino = ino; o->target.ino = destination;
	o->source.igen = 3; o->target.igen = 4;
	o->source_mnt_id = 31; o->target_mnt_id = 32;
}
static void mount_rule(unsigned int profile, const char *path, unsigned long long id,
		unsigned long long parent, unsigned long long root)
{
	unsigned int i = config.mount_count++;
	struct skp_group_mount_object *o = &mounts[i];
	config.mounts[i].profile_id = o->profile_id = profile;
	strcpy(config.mounts[i].path, path); o->chain_count = root ? 3 : 2;
	o->ids[0] = id; o->ids[1] = parent;
	o->cookies[0] = id + 1000; o->cookies[1] = parent + 1000;
	if (root) { o->ids[2] = root; o->cookies[2] = root + 1000; }
}
static int valid(void)
{
	return skp_full_objects_resolved_validate(&config, redirects, mounts);
}
static int find(const struct skp_subject_context *c, unsigned long long dev,
		unsigned long long ino, unsigned int gen, unsigned long long mnt, unsigned int way)
{
	return skp_full_redirect_find(&config, redirects, c, dev, ino, gen, mnt, way);
}
static void query(const struct skp_subject_context *c, unsigned long long cookie,
		unsigned long long id, unsigned long long parent, unsigned int hidden,
		unsigned long long shown, unsigned long long shown_parent)
{
	struct skp_mount_query_result result;
	memset(&result, 0xa5, sizeof(result));
	skp_full_mount_lookup(&config, mounts, c, cookie, id, parent, &result);
	expect(result.hidden == hidden && result.shown_id == shown &&
	       result.parent_id == shown_parent && !result.generation &&
	       !result.legacy_allowed && !result.uncertain && !result.reserved,
	       "mount decision and zero copied metadata");
}

static void test_empty_and_subjects(void)
{
	struct skp_subject_context a = caller(10101), b = caller(10102), c = caller(10103);
	struct skp_subject_context normal = caller(10404), root = caller(0), worker = caller(99001);
	init();
	expect(!skp_full_objects_validate(&config) && !valid(), "empty five-family accepted");
	expect(skp_full_objects_resolved_validate(&config, NULL, NULL) == 0, "empty permits no arrays");
	query(&a, 1010, 10, 1, 0, 0, 0);
	redirect(7, "/fixture/a", "/fixture/b", 12, 40, 41);
	redirect(19, "/fixture/a", "/fixture/c", 12, 40, 42);
	redirect(0, "/fixture/default", "/fixture/default-target", 12, 50, 51);
	mount_rule(7, "/fixture/mount", 10, 1, 0);
	mount_rule(19, "/fixture/mount", 20, 1, 0);
	expect(!valid(), "cross-profile same source and mount path accepted");
	expect(find(&a, 12, 40, 3, 31, SKP_REDIRECT_FORWARD) == 0, "profile A forward");
	expect(find(&b, 12, 40, 3, 31, SKP_REDIRECT_FORWARD) == 1, "profile B forward");
	expect(find(&a, 12, 41, 4, 32, SKP_REDIRECT_REVERSE) == 0, "same profile reverse");
	expect(find(&a, 0, 41, 0, 32, SKP_REDIRECT_IDS) == 0, "fdinfo exact target ino and mount");
	expect(find(&a, 12, 41, 4, 31, SKP_REDIRECT_IDS) == -1, "fdinfo wrong mount refuses");
	expect(find(&a, 12, 41, 4, 0, SKP_REDIRECT_IDS) == -1, "fdinfo missing mount refuses");
	expect(find(&a, 13, 40, 3, 31, 0) == -1, "raw dev exact");
	expect(find(&a, 12, 40, 4, 31, 0) == -1, "generation exact");
	expect(find(&a, 12, 40, 3, 31, 3) == -1, "unknown direction refuses");
	expect(find(&a, 12, 0, 3, 31, 0) == -1, "zero inode refuses");
	expect(find(&c, 12, 40, 3, 31, 0) == -1, "empty profile no fallback");
	expect(find(&normal, 12, 40, 3, 31, 0) == -1, "default no fallback to group");
	expect(find(&normal, 12, 50, 3, 31, 0) == 2, "default rules independent");
	query(&a, 1010, 10, 1, 1, 1, 1);
	query(&b, 1010, 10, 1, 0, 10, 1);
	query(&a, 9999, 10, 1, 0, 10, 1);
	query(&a, 0, 10, 1, 1, 1, 1);
	query(&a, 1011, 11, 10, 0, 11, 1); /* descendant is visible; parent is remapped */
	a.precise_manager = 1;
	expect(find(&a, 12, 40, 3, 31, 0) == -1, "manager exemption");
	query(&a, 1010, 10, 1, 0, 0, 0);
	a.precise_manager = 0;
	config.objects.paths.subjects.whitelist_count = 1;
	config.objects.paths.subjects.whitelist[0] = 10101;
	expect(find(&a, 12, 40, 3, 31, 0) == -1, "whitelist exemption");
	query(&a, 1010, 10, 1, 0, 0, 0);
	config.objects.paths.subjects.whitelist_count = config.objects.paths.subjects.whitelist[0] = 0;
	config.objects.paths.subjects.flags = SKP_SUBJECT_EXEMPT_ROOT;
	expect(find(&root, 12, 50, 3, 31, 0) == -1, "root exemption real UID");
	config.objects.paths.subjects.flags = 0;
	expect(find(&root, 12, 50, 3, 31, 0) == 2, "root without exemption default profile");
	worker.worker_verified = 1; worker.origin_uid = 10101; worker.origin_facts_generation = 17;
	expect(find(&worker, 12, 40, 3, 31, 0) == 0, "verified worker canonical facts");
	worker.origin_facts_generation++;
	expect(find(&worker, 12, 40, 3, 31, 0) == -1, "stale worker facts no attribution");
}

static void test_validation(void)
{
	unsigned int i;
	const char *bad[] = { "", "/", "relative", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\nb" };
	init(); redirect(7, "/fixture/a", "/fixture/b", 12, 40, 41);
	mount_rule(7, "/fixture/mount", 10, 1, 0); saved = config;
	expect(skp_full_objects_validate(NULL) == SKP_GROUP_PATHS_ERR_ARGUMENT, "null config");
	expect(skp_full_objects_resolved_validate(&config, NULL, mounts) == SKP_GROUP_PATHS_ERR_ARGUMENT, "missing redirect objects");
	expect(skp_full_objects_resolved_validate(&config, redirects, NULL) == SKP_GROUP_PATHS_ERR_ARGUMENT, "missing mount objects");
	config.version = 2; expect(skp_full_objects_validate(&config) != 0, "future version rejected"); config = saved;
	config.reserved = 1; expect(skp_full_objects_validate(&config) != 0, "reserved header rejected"); config = saved;
	config.redirect_count = 65; expect(skp_full_objects_validate(&config) != 0, "redirect capacity"); config = saved;
	config.mount_count = 65; expect(skp_full_objects_validate(&config) != 0, "mount capacity"); config = saved;
	config.objects.paths.subjects.version = 2; expect(skp_full_objects_validate(&config) != 0, "embedded core validation"); config = saved;
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
		strcpy(config.redirects[0].source, bad[i]); expect(skp_full_objects_validate(&config) != 0, "bad source"); config = saved;
		memset(config.redirects[0].target, 0, 256); strcpy(config.redirects[0].target, bad[i]); expect(skp_full_objects_validate(&config) != 0, "bad target"); config = saved;
		memset(config.mounts[0].path, 0, 256); strcpy(config.mounts[0].path, bad[i]); expect(skp_full_objects_validate(&config) != 0, "bad mount"); config = saved;
	}
	for (i = 0; i < 3; ++i) {
		char *field = i == 0 ? config.redirects[0].source : i == 1 ? config.redirects[0].target : config.mounts[0].path;
		field[255] = 'x'; expect(skp_full_objects_validate(&config) != 0, "path zero tail"); config = saved;
		field = i == 0 ? config.redirects[0].source : i == 1 ? config.redirects[0].target : config.mounts[0].path;
		memset(field, 'x', 256); field[0] = '/'; expect(skp_full_objects_validate(&config) != 0, "unterminated path"); config = saved;
	}
	for (i = 1; i < SKP_GROUP_REDIRECTS_MAX; ++i) {
		config.redirects[i].flags = 1; expect(skp_full_objects_validate(&config) == SKP_GROUP_PATHS_ERR_TAIL, "unused redirect zero tail"); config = saved;
	}
	for (i = 1; i < SKP_GROUP_MOUNTS_MAX; ++i) {
		config.mounts[i].flags = 1; expect(skp_full_objects_validate(&config) == SKP_GROUP_PATHS_ERR_TAIL, "unused mount zero tail"); config = saved;
	}
	config.redirects[0].flags = 1; expect(skp_full_objects_validate(&config) != 0, "redirect flags"); config = saved;
	config.mounts[0].flags = 1; expect(skp_full_objects_validate(&config) != 0, "mount flags"); config = saved;
	config.redirects[0].profile_id = 2; expect(skp_full_objects_validate(&config) != 0, "redirect undeclared profile"); config = saved;
	config.mounts[0].profile_id = 2; expect(skp_full_objects_validate(&config) != 0, "mount undeclared profile"); config = saved;
	strcpy(config.redirects[0].target, config.redirects[0].source); expect(skp_full_objects_validate(&config) != 0, "self redirect"); config = saved;
	for (i = 0; i < 4; ++i) {
		config.redirect_count = 2; config.redirects[1].profile_id = 7;
		strcpy(config.redirects[1].source, i == 0 ? "/fixture/a" : i == 1 ? "/fixture/b" : "/fixture/c");
		strcpy(config.redirects[1].target, i == 2 ? "/fixture/a" : i == 3 ? "/fixture/b" : "/fixture/d");
		expect(skp_full_objects_validate(&config) != 0, "lexical source/target overlap or chain"); config = saved;
	}
	config.mount_count = 2; config.mounts[1] = config.mounts[0];
	expect(skp_full_objects_validate(&config) != 0, "same profile mount duplicate"); config = saved;
}

static void test_resolved(void)
{
	struct skp_group_redirect_object r;
	struct skp_group_mount_object m;
	struct skp_subject_context a = caller(10101);
	unsigned int i;
	init(); redirect(7, "/fixture/a", "/fixture/b", 12, 40, 41);
	mount_rule(7, "/fixture/mount", 10, 1, 0); r = redirects[0]; m = mounts[0];
	for (i = 0; i < 10; ++i) {
		if (i == 0) redirects[0].profile_id = 19;
		if (i == 1) redirects[0].reserved = 1;
		if (i == 2) redirects[0].source.reserved = 1;
		if (i == 3) redirects[0].target.reserved = 1;
		if (i == 4) redirects[0].source.ino = 0;
		if (i == 5) redirects[0].target.ino = 0;
		if (i == 6) redirects[0].source_mnt_id = 0;
		if (i == 7) redirects[0].target_mnt_id = 0;
		if (i == 8) redirects[0].source_mnt_id = 2147483648ULL;
		if (i == 9) redirects[0].target_mnt_id = 2147483648ULL;
		expect(valid() == SKP_GROUP_PATHS_ERR_OBJECT, "invalid resolved redirect key"); redirects[0] = r;
	}
	redirects[0].target = redirects[0].source;
	expect(valid() == SKP_GROUP_PATHS_ERR_ALIAS, "same resolved object self alias"); redirects[0] = r;
	for (i = 0; i < 4; ++i) {
		redirect(7, "/fixture/c", "/fixture/d", 13, 50, 51);
		if (i == 0) redirects[1].source = r.source;
		if (i == 1) redirects[1].target = r.target;
		if (i == 2) redirects[1].source = r.target;
		if (i == 3) redirects[1].target = r.source;
		expect(valid() == SKP_GROUP_PATHS_ERR_ALIAS, "same profile resolved overlap");
		config.redirect_count = 1; memset(&config.redirects[1], 0, sizeof(config.redirects[1]));
	}
	/* Different filesystems may have equal inode+mnt projections: fdinfo must
	 * refuse the ambiguous projection even if exact reverse identity is safe. */
	redirect(7, "/fixture/c", "/fixture/d", 13, 50, 41);
	expect(!valid(), "distinct exact target identities");
	expect(find(&a, 12, 41, 4, 32, SKP_REDIRECT_REVERSE) == 0, "exact reverse disambiguates raw device");
	expect(find(&a, 0, 41, 0, 32, SKP_REDIRECT_IDS) == -1, "ambiguous fdinfo refuses guessing");
	for (i = 0; i < 9; ++i) {
		if (i == 0) mounts[0].profile_id = 19;
		if (i == 1) mounts[0].chain_count = 1;
		if (i == 2) mounts[0].chain_count = 33;
		if (i == 3) mounts[0].cookies[0] = 0;
		if (i == 4) mounts[0].ids[0] = 0;
		if (i == 5) mounts[0].ids[0] = 2147483648ULL;
		if (i == 6) mounts[0].cookies[1] = mounts[0].cookies[0];
		if (i == 7) mounts[0].ids[1] = mounts[0].ids[0];
		if (i == 8) mounts[0].ids[31] = 1;
		expect(valid() != 0, "malformed resolved mount chain"); mounts[0] = m;
	}
	for (i = 2; i < SKP_MOUNT_CHAIN_MAX; ++i) {
		mounts[0].cookies[i] = 123; expect(valid() == SKP_GROUP_PATHS_ERR_TAIL, "chain cookie tail"); mounts[0] = m;
		mounts[0].ids[i] = 123; expect(valid() == SKP_GROUP_PATHS_ERR_TAIL, "chain ID tail"); mounts[0] = m;
	}
	mount_rule(7, "/fixture/othermount", 20, 1, 0);
	mounts[1].cookies[0] = mounts[0].cookies[0]; expect(valid() == SKP_GROUP_PATHS_ERR_ALIAS, "same profile mount cookie alias");
	mounts[1].cookies[0] = 1020; mounts[1].ids[0] = 10;
	expect(valid() == SKP_GROUP_PATHS_ERR_ALIAS, "same profile mount ID alias");
}

static void test_mount_ancestors_and_capacity(void)
{
	struct skp_subject_context a = caller(10101), b = caller(10102);
	unsigned int i;
	init();
	mount_rule(7, "/fixture/childmount", 10, 20, 1);
	mount_rule(7, "/fixture/parentmount", 20, 1, 0);
	mount_rule(19, "/fixture/samechildmount", 10, 20, 1);
	expect(!valid(), "nested selected mounts across profiles");
	query(&a, 1010, 10, 20, 1, 1, 1);
	query(&b, 1010, 10, 20, 1, 20, 20);
	query(&a, 1030, 30, 10, 0, 30, 1);
	init();
	for (i = 0; i < SKP_GROUP_REDIRECTS_MAX; ++i) {
		char source[64], target[64];
		snprintf(source, sizeof(source), "/fixture/source/%u", i);
		snprintf(target, sizeof(target), "/fixture/target/%u", i);
		redirect(7, source, target, 12, i + 1, i + 1000);
	}
	for (i = 0; i < SKP_GROUP_MOUNTS_MAX; ++i) {
		char path[64]; snprintf(path, sizeof(path), "/fixture/mount/%u", i);
		mount_rule(7, path, i + 2, 1, 0);
	}
	expect(!valid(), "maximum family counts");
	for (i = 0; i < SKP_GROUP_REDIRECTS_MAX; ++i) {
		expect(find(&a, 12, i + 1, 3, 31, 0) == (int)i, "all maximum forward slots");
		expect(find(&a, 12, i + 1000, 4, 32, 1) == (int)i, "all maximum reverse slots");
		expect(find(&b, 12, i + 1, 3, 31, 0) == -1, "maximum isolation miss");
	}
	for (i = 0; i < SKP_GROUP_MOUNTS_MAX; ++i)
		query(&a, i + 1002, i + 2, 1, 1, 1, 1);
	/* A 32-link chain is accepted; every tail slot is actual topology input. */
	config.mount_count = 1; memset(config.mounts + 1, 0, sizeof(config.mounts) - sizeof(config.mounts[0]));
	mounts[0].chain_count = 32;
	for (i = 0; i < 32; ++i) { mounts[0].cookies[i] = 3000 + i; mounts[0].ids[i] = 2000 + i; }
	expect(!valid(), "maximum chain depth");
	query(&a, 3000, 2000, 2001, 1, 2001, 2001);
}

int main(void)
{
	test_empty_and_subjects(); test_validation(); test_resolved(); test_mount_ancestors_and_capacity();
	printf("FULL_OBJECTS_HOST checks=%u passed=true kernel_calls=false production_source=true\n", checks);
	return 0;
}
