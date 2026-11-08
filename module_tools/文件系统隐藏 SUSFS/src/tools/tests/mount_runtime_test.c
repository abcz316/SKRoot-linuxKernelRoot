// SPDX-License-Identifier: GPL-2.0-only
#include "mount_runtime_shim.h"
#include "../../kernel/skp_mount_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int checks, allocations, paths, refs, lookups, fail_lookup, missing_symbol;
static bool fail_alloc, unstable_read;
static bool change_root_during_topology;
static bool change_topology_on_retry, change_mount_root_on_lookup;
static unsigned int sequence_reads, sequence_retries;
static struct mnt_namespace ns, other_ns;
static struct nsproxy proxy = { &ns };
static struct fs_struct fs;
static struct task_struct task = { &proxy, &fs };
struct task_struct *current = &task;
static seqlock_t topology;
static struct mount mounts[SKP_GROUP_MOUNTS_MAX + SKP_MOUNT_CHAIN_MAX + 2];
static struct dentry dentries[SKP_GROUP_MOUNTS_MAX + SKP_MOUNT_CHAIN_MAX + 2], subdir;
static struct skp_full_objects_config config;
static struct skp_group_mounts_runtime *runtime;

static void expect(bool condition, const char *message)
{
	checks++;
	if (!condition) { fprintf(stderr, "FAIL %u %s\n", checks, message); exit(1); }
}
void *kvzalloc(size_t size, unsigned int flags)
{
	expect(flags == GFP_KERNEL && !topology.locked, "allocation before topology lock");
	allocations++;
	return fail_alloc ? NULL : calloc(1, size);
}
void kvfree(const void *pointer) { expect(!topology.locked, "free outside topology lock"); free((void *)pointer); }
struct vfsmount *mntget(struct vfsmount *mount)
{
	expect(topology.locked, "capture pins parents atomically under topology lock");
	mount->references++; refs++;
	return mount;
}
void mntput(struct vfsmount *mount)
{
	expect(!topology.locked && mount->references && refs, "release owned mount outside lock");
	mount->references--; refs--;
}
int kern_path(const char *name, unsigned int flags, struct path *path)
{
	unsigned int index = 0;
	bool sub = false;
	expect(flags == LOOKUP_FOLLOW && !topology.locked, "ordinary path resolution outside lock");
	if (++lookups == fail_lookup) return -ENOENT;
	if (!strcmp(name, "/root")) index = 0;
	else if (sscanf(name, "/mount/%u", &index) == 1) index += 2;
	else if (sscanf(name, "/alias/%u", &index) == 1) index += 2;
	else if (!strcmp(name, "/subdir")) { index = 2; sub = true; }
	else return -ENOENT;
	if (index >= sizeof(mounts) / sizeof(mounts[0])) return -ENOENT;
	path->mnt = &mounts[index].mnt;
	path->dentry = sub ? &subdir : &dentries[index];
	path->mnt->references++; path->dentry->references++; paths++;
	if (change_mount_root_on_lookup) {
		fs.root.mnt->mnt_root = &subdir;
		change_mount_root_on_lookup = false;
	}
	return 0;
}
void path_put(const struct path *path)
{
	expect(!topology.locked && paths && path->mnt->references && path->dentry->references,
	       "resolved path released outside lock");
	path->mnt->references--; path->dentry->references--; paths--;
}
void get_mnt_ns(struct mnt_namespace *space) { space->references++; }
void get_fs_root(struct fs_struct *context, struct path *path)
{
	expect(!topology.locked, "publisher root captured outside topology lock");
	*path = context->root; path->mnt->references++; path->dentry->references++; paths++;
}
static void put_namespace(struct mnt_namespace *space)
{
	expect(!topology.locked && space->references, "namespace released after mount refs");
	space->references--;
}
unsigned long find_kernel_symbol_exact(const char *name)
{
	if (!strcmp(name, "mount_lock")) return missing_symbol == 1 ? 0 : (unsigned long)&topology;
	if (!strcmp(name, "put_mnt_ns")) return missing_symbol == 2 ? 0 : (unsigned long)put_namespace;
	expect(false, "only authorized topology symbols resolved"); return 0;
}
void read_seqlock_excl(seqlock_t *lock) { expect(!lock->locked, "topology exclusive lock"); lock->locked = true; }
void read_sequnlock_excl(seqlock_t *lock) { expect(lock->locked, "topology unlock"); lock->locked = false; }
unsigned int raw_read_seqcount(const seqcount_t *counter)
{
	sequence_reads++;
	if (change_root_during_topology && counter == &topology.seqcount.seqcount) {
		fs.seq.seqcount.sequence += 2;
		change_root_during_topology = false;
	}
	return counter->sequence;
}
bool read_seqcount_retry(const seqcount_t *counter, unsigned int sequence)
{
	sequence_retries++;
	if (change_topology_on_retry && counter == &topology.seqcount.seqcount) {
		topology.seqcount.seqcount.sequence += 2;
		change_topology_on_retry = false;
	}
	return unstable_read || counter->sequence != sequence;
}

static void base(unsigned int count)
{
	unsigned int i;
	expect(!runtime && !paths && !refs && !ns.references && !other_ns.references, "all prior refs released");
	for (i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i) {
		expect(!mounts[i].mnt.references && !dentries[i].references, "fixture ref balance");
		mounts[i].mnt.mnt_root = &dentries[i];
		mounts[i].mnt_parent = i ? &mounts[0] : &mounts[i];
		mounts[i].mnt_ns = &ns;
		mounts[i].mnt_id = (int)i + 1;
	}
	memset(&config, 0, sizeof(config));
	config.objects.paths.subjects.version = SKP_SUBJECT_POLICY_VERSION;
	config.objects.paths.subjects.facts_generation = 1;
	config.objects.paths.subjects.profile_count = 2;
	config.objects.paths.subjects.profiles[0] = 0;
	config.objects.paths.subjects.profiles[1] = 1;
	config.objects.paths.version = SKP_GROUP_PATHS_VERSION;
	config.objects.version = SKP_GROUP_OBJECTS_VERSION;
	config.version = SKP_FULL_OBJECTS_VERSION;
	config.mount_count = count;
	for (i = 0; i < count; ++i) {
		config.mounts[i].profile_id = i % 2;
		snprintf(config.mounts[i].path, sizeof(config.mounts[i].path), "/mount/%u", i);
	}
	allocations = lookups = fail_lookup = missing_symbol = 0;
	fail_alloc = unstable_read = false;
	change_root_during_topology = change_topology_on_retry = change_mount_root_on_lookup = false;
	topology.locked = false; topology.seqcount.seqcount.sequence = 0;
	proxy.mnt_ns = &ns; task.nsproxy = &proxy; task.fs = &fs;
	fs.root.mnt = &mounts[0].mnt; fs.root.dentry = &dentries[0]; fs.seq.seqcount.sequence = 0;
}
static void release(void)
{
	skp_group_mounts_runtime_free(runtime); runtime = NULL;
	expect(!paths && !refs && !ns.references && !other_ns.references, "complete runtime cleanup");
}
static void failure(int error)
{
	expect(skp_group_mounts_runtime_prepare(&config, &runtime) == error, "expected preparation error");
	expect(!runtime && !paths && !refs && !ns.references, "failure exposes no candidate/leaks");
}

int main(void)
{
	unsigned int i;
	base(0); missing_symbol = 1;
	expect(!skp_group_mounts_runtime_prepare(&config, &runtime), "zero mounts need no symbols");
	expect(skp_group_mounts_runtime_stable(runtime), "zero mount snapshot stable"); release();
	base(1); fail_alloc = true; failure(-ENOMEM);
	for (i = 1; i <= 2; ++i) { base(1); missing_symbol = i; failure(-EOPNOTSUPP); }
	base(1); task.nsproxy = NULL; failure(-ENOENT);
	base(1); proxy.mnt_ns = NULL; failure(-ENOENT);
	base(1); task.fs = NULL; failure(-ENOENT);
	base(1); fs.root.dentry = &subdir; failure(-EOPNOTSUPP);
	base(1); fs.root.mnt = &mounts[1].mnt; fs.root.dentry = &dentries[1]; failure(-ESTALE);
	base(1); mounts[0].mnt_ns = &other_ns; failure(-EOPNOTSUPP);
	base(1); strcpy(config.mounts[0].path, "/subdir"); failure(-EINVAL);
	base(1); memset(config.mounts[0].path, 0, sizeof(config.mounts[0].path));
	strcpy(config.mounts[0].path, "/root"); failure(-EINVAL);
	base(1); mounts[2].mnt_ns = &other_ns; failure(-ESTALE);
	base(1); mounts[2].mnt_parent = NULL; failure(-ESTALE);
	base(1); mounts[2].mnt_id = 0; failure(-ESTALE);
	base(1); mounts[2].mnt_parent = &mounts[1]; mounts[1].mnt_ns = &other_ns; failure(-ESTALE);
	base(2); config.mounts[1].profile_id = config.mounts[0].profile_id;
	strcpy(config.mounts[1].path, "/alias/0"); failure(-EEXIST);
	base(2); strcpy(config.mounts[1].path, "/alias/0");
	expect(!skp_group_mounts_runtime_prepare(&config, &runtime), "cross-profile same mount permitted"); release();
	base(1);
	for (i = 2; i < SKP_MOUNT_CHAIN_MAX + 3; ++i) mounts[i].mnt_parent = &mounts[i + 1];
	failure(-E2BIG);
	for (i = 1; i <= SKP_GROUP_MOUNTS_MAX; ++i) { base(SKP_GROUP_MOUNTS_MAX); fail_lookup = i; failure(-ENOENT); }
	base(SKP_GROUP_MOUNTS_MAX);
	expect(!skp_group_mounts_runtime_prepare(&config, &runtime), "maximum mount snapshot prepared");
	expect(skp_group_mounts_runtime_stable(runtime), "all held topology initially stable");
	expect(skp_group_mounts_objects(runtime)[0].cookies[0] == (u64)(unsigned long)&mounts[2].mnt, "exact mount cookie retained");
	mounts[2].mnt_id++;
	expect(!skp_group_mounts_runtime_stable(runtime), "re-ID makes all answers uncertain"); mounts[2].mnt_id--;
	mounts[2].mnt_ns = &other_ns;
	expect(!skp_group_mounts_runtime_stable(runtime), "namespace change is not implicit widening"); mounts[2].mnt_ns = &ns;
	mounts[2].mnt_parent = &mounts[1];
	expect(!skp_group_mounts_runtime_stable(runtime), "reparent invalidates snapshot"); mounts[2].mnt_parent = &mounts[0];
	mounts[0].mnt_id++;
	expect(!skp_group_mounts_runtime_stable(runtime), "visible ancestor ID is also held/validated"); mounts[0].mnt_id--;
	unstable_read = true; expect(!skp_group_mounts_runtime_stable(runtime), "concurrent topology write uncertain"); unstable_read = false;
	sequence_reads = sequence_retries = 0;
	topology.seqcount.seqcount.sequence = 1; topology.locked = true;
	expect(!skp_group_mounts_runtime_stable(runtime) && sequence_reads == 2 && sequence_retries == 1,
	       "odd writer on same CPU returns immediately, no wait or retry");
	topology.seqcount.seqcount.sequence = 2; topology.locked = false;
	sequence_reads = sequence_retries = 0; fs.seq.seqcount.sequence = 1;
	expect(!skp_group_mounts_runtime_stable(runtime) && sequence_reads == 1 && !sequence_retries,
	       "odd fs root writer returns immediately without taking fs lock");
	fs.seq.seqcount.sequence = 2;
	proxy.mnt_ns = &other_ns;
	expect(!skp_group_mounts_runtime_stable(runtime), "different reader namespace stays native"); proxy.mnt_ns = &ns;
	fs.root.dentry = &subdir;
	expect(!skp_group_mounts_runtime_stable(runtime), "different chroot dentry stays native"); fs.root.dentry = &dentries[0];
	fs.root.mnt = &mounts[1].mnt;
	expect(!skp_group_mounts_runtime_stable(runtime), "different root mount stays native"); fs.root.mnt = &mounts[0].mnt;
	change_root_during_topology = true;
	expect(!skp_group_mounts_runtime_stable(runtime), "fs root counter rechecked after mount validation");
	task.fs = NULL; expect(!skp_group_mounts_runtime_stable(runtime), "kernel thread has no guessed fs identity"); task.fs = &fs;
	expect(skp_group_mounts_runtime_stable(runtime), "restored topology stable"); release();
	expect(!skp_group_mounts_runtime_stable(NULL) && !skp_group_mounts_objects(NULL), "null runtime refused");
	printf("MOUNT_RUNTIME_HOST checks=%u passed=true kernel_calls=false production_source=true\n", checks);
	return 0;
}
