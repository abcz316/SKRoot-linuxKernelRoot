// SPDX-License-Identifier: GPL-2.0-only
/* Links both production resolvers; no replacement resolver implementation. */
#include "../../kernel/skp_group_objects_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOTAL (SKP_GROUP_PATHS_MAX + SKP_GROUP_KSTATS_MAX + SKP_GROUP_MAPS_MAX)
static struct fixture {
	char name[64];
	struct super_block sb;
	struct inode inode;
	struct dentry dentry;
	struct vfsmount mount;
} fixtures[TOTAL];
static unsigned int checks, allocations, lookups, grabs, paths, inodes;
static unsigned int fail_alloc, fail_lookup, fail_grab, missing_inode;
static struct skp_group_objects_runtime *output;
static int preparing;

static void expect(int condition, const char *label)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL check=%u %s\n", checks, label);
		exit(1);
	}
}
void *kvzalloc(size_t size, unsigned int flags)
{
	expect(flags == GFP_KERNEL, "process allocation");
	if (++allocations == fail_alloc)
		return NULL;
	return calloc(1, size);
}
void kvfree(const void *memory) { free((void *)memory); }
int kern_path(const char *name, unsigned int flags, struct path *path)
{
	unsigned int i;
	expect(!preparing || !output, "candidate never exposed before complete");
	expect(flags == LOOKUP_FOLLOW, "normal follow resolution");
	if (++lookups == fail_lookup)
		return -ENOENT;
	for (i = 0; i < TOTAL; ++i) {
		if (strcmp(fixtures[i].name, name))
			continue;
		path->dentry = &fixtures[i].dentry;
		path->mnt = &fixtures[i].mount;
		path->dentry->references++;
		path->mnt->references++;
		paths++;
		return 0;
	}
	return -ENOENT;
}
void path_put(const struct path *path)
{
	expect(path->dentry && path->mnt, "only acquired path released");
	expect(path->dentry->references && path->mnt->references && paths, "path owned");
	path->dentry->references--;
	path->mnt->references--;
	paths--;
}
struct inode *d_inode(const struct dentry *dentry)
{
	return missing_inode == lookups ? NULL : dentry->inode;
}
struct inode *igrab(struct inode *inode)
{
	if (++grabs == fail_grab)
		return NULL;
	inode->references++;
	inodes++;
	return inode;
}
void iput(struct inode *inode)
{
	expect(inode->references && inodes, "inode held");
	inode->references--;
	inodes--;
}
void spin_lock(struct runtime_test_spinlock *lock)
{
	expect(!lock->locked, "dentry not already locked");
	lock->locked = true;
}
void spin_unlock(struct runtime_test_spinlock *lock)
{
	expect(lock->locked, "unlock held dentry");
	lock->locked = false;
}
long strscpy(char *destination, const char *source, size_t capacity)
{
	size_t n = strlen(source);
	if (n >= capacity)
		return -E2BIG;
	memcpy(destination, source, n + 1);
	return (long)n;
}
static void reset(void)
{
	unsigned int i;
	expect(!output && !paths && !inodes, "preceding test cleaned references");
	allocations = lookups = grabs = 0;
	fail_alloc = fail_lookup = fail_grab = missing_inode = 0;
	for (i = 0; i < TOTAL; ++i) {
		expect(!fixtures[i].inode.references && !fixtures[i].dentry.references &&
		       !fixtures[i].mount.references, "fixture refs balanced");
		expect(fixtures[i].inode.i_mode == 0600, "permissions unchanged");
		fixtures[i].sb.s_dev = 123;
		fixtures[i].inode.i_ino = i + 1;
	}
}
static struct skp_group_objects_config config;
static void prepare_config(unsigned int pc, unsigned int kc, unsigned int mc)
{
	unsigned int i;
	memset(&config, 0, sizeof(config));
	config.paths.subjects.version = SKP_SUBJECT_POLICY_VERSION;
	config.paths.subjects.facts_generation = 1;
	config.paths.subjects.profile_count = 2;
	config.paths.subjects.profiles[1] = 7;
	config.paths.version = SKP_GROUP_PATHS_VERSION;
	config.paths.path_count = pc;
	config.version = SKP_GROUP_OBJECTS_VERSION;
	config.kstat_count = kc;
	config.map_count = mc;
	for (i = 0; i < pc; ++i)
		strcpy(config.paths.rules[i].path, fixtures[i].name);
	for (i = 0; i < kc; ++i) {
		strcpy(config.kstats[i].path, fixtures[pc + i].name);
		config.kstats[i].values.flags = 1;
		config.kstats[i].values.ino = 987;
	}
	for (i = 0; i < mc; ++i)
		strcpy(config.maps[i].path, fixtures[pc + kc + i].name);
}
static int prepare(void)
{
	int result;
	preparing = 1;
	result = skp_group_objects_runtime_prepare(&config, &output);
	preparing = 0;
	return result;
}
static void release(void)
{
	skp_group_objects_runtime_free(output);
	output = NULL;
	expect(!paths && !inodes, "all successful refs drained");
}
int main(void)
{
	unsigned int i;
	for (i = 0; i < TOTAL; ++i) {
		snprintf(fixtures[i].name, sizeof(fixtures[i].name), "/fixture/%u", i);
		fixtures[i].inode.i_sb = &fixtures[i].sb;
		fixtures[i].inode.i_mode = 0600;
		fixtures[i].dentry.inode = &fixtures[i].inode;
		fixtures[i].dentry.d_name.name = (unsigned char *)(strrchr(fixtures[i].name, '/') + 1);
	}
	reset();
	prepare_config(0, 0, 0);
	expect(!prepare(), "empty complete candidate accepted");
	expect(output && output->paths && output->resolved_count == 0, "empty family authoritative");
	release();
	prepare_config(SKP_GROUP_PATHS_MAX, SKP_GROUP_KSTATS_MAX, SKP_GROUP_MAPS_MAX);
	reset();
	expect(!prepare(), "maximum full candidate accepted");
	expect(paths == TOTAL && inodes == TOTAL, "all family identities pinned");
	expect(!memcmp(&output->config.paths.subjects, &output->paths->config.subjects,
		       sizeof(config.paths.subjects)), "one identical immutable subject snapshot");
	expect(output->kstats[0].dev == 123 && output->maps[0].ino == 161, "raw exact keys");
	config.kstats[0].values.ino = 999;
	expect(output->config.kstats[0].values.ino == 987, "private immutable config copy");
	release();
	for (i = 1; i <= TOTAL; ++i) {
		reset(); fail_lookup = i;
		expect(prepare() == -ENOENT && !output, "every failed resolution rejects whole candidate");
		expect(!paths && !inodes, "resolution failure fully unwound");
		reset(); fail_grab = i;
		expect(prepare() == -ESTALE && !output, "every failed inode pin rejects whole candidate");
		expect(!paths && !inodes, "pin failure fully unwound");
		reset(); missing_inode = i;
		expect(prepare() == -ENOENT && !output, "missing inode fully rejected");
		expect(!paths && !inodes, "negative inode fully unwound");
	}
	for (i = 1; i <= 2; ++i) {
		reset(); fail_alloc = i;
		expect(prepare() == -ENOMEM && !output && !paths && !inodes, "both candidate allocation failures");
	}
	prepare_config(1, 2, 2);
	reset(); fixtures[2].inode.i_ino = fixtures[1].inode.i_ino;
	expect(prepare() == -EEXIST && !output && !paths && !inodes, "same profile kstat alias refused");
	config.kstats[1].profile_id = 7;
	expect(!prepare(), "cross profile kstat alias allowed"); release();
	reset(); fixtures[4].inode.i_ino = fixtures[3].inode.i_ino;
	expect(prepare() == -EEXIST && !output && !paths && !inodes, "same profile map alias refused");
	config.maps[1].profile_id = 7;
	expect(!prepare(), "cross profile map alias allowed"); release();
	reset(); fixtures[3].inode.i_ino = fixtures[1].inode.i_ino;
	expect(!prepare(), "cross family key coexistence allowed"); release();
	reset(); config.reserved = 1;
	expect(prepare() == -EINVAL && !output && !allocations && !lookups, "invalid rejected before VFS");
	expect(skp_group_objects_runtime_prepare(NULL, NULL) == -EINVAL, "null output rejected");
	skp_group_objects_runtime_free(NULL);
	printf("GROUP_OBJECTS_RUNTIME_HOST checks=%u passed=true kernel_calls=false production_source=true\n", checks);
	return 0;
}
