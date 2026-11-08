// SPDX-License-Identifier: GPL-2.0-only
/* Compile this with the production resolver, subject core and path core using
 * -DSKP_GROUP_PATHS_RUNTIME_HOSTTEST -pthread. All VFS calls below are typed
 * deterministic doubles. No syscalls, App impersonation or kernel tests. */
#include "../../kernel/skp_group_paths_runtime.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURES SKP_GROUP_PATHS_MAX

struct fixture {
	char path[SKP_GROUP_PATH_LEN];
	unsigned char basename[SKP_GROUP_PATH_LEN + 32];
	struct super_block superblock;
	struct inode inode;
	struct dentry dentry;
	struct vfsmount mount;
	unsigned int initial_mode;
};

static struct fixture fixtures[FIXTURES];
static unsigned int fixture_count;
static _Atomic unsigned int checks;

static struct {
	unsigned int allocation_calls, free_calls, live_allocations;
	unsigned int lookup_calls, paths_acquired, paths_released;
	unsigned int grab_calls, inodes_acquired, inodes_released;
	unsigned int lock_calls, unlock_calls;
	unsigned int fail_allocate, fail_lookup, fail_grab;
	void *allocation;
	struct skp_group_paths_runtime **watched_output;
	bool watch_output;
	bool gate_enabled, gate_entered, gate_release;
} state;

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;

static void expect(int condition, const char *message)
{
	unsigned int number = atomic_fetch_add_explicit(&checks, 1, memory_order_relaxed) + 1;

	if (!condition) {
		fprintf(stderr, "FAIL: %s (check %u)\n", message, number);
		exit(1);
	}
}

static void expect_output_unpublished(void)
{
	if (state.watch_output)
		expect(state.watched_output && !*state.watched_output,
		       "output remains unpublished throughout candidate preparation");
}

static void expect_no_references(void)
{
	unsigned int i;

	expect(state.paths_acquired == state.paths_released, "all path references released");
	expect(state.inodes_acquired == state.inodes_released, "all explicit inode references released");
	expect(state.lock_calls == state.unlock_calls, "all dentry locks released");
	for (i = 0; i < fixture_count; ++i) {
		expect(fixtures[i].dentry.references == 0, "no dentry reference leaks");
		expect(fixtures[i].mount.references == 0, "no mount reference leaks");
		expect(fixtures[i].inode.references == 0, "no inode reference leaks");
		expect(!fixtures[i].dentry.d_lock.locked, "no held dentry lock survives");
		expect(fixtures[i].inode.i_mode == fixtures[i].initial_mode,
		       "resolver never changes target permissions");
	}
}

void *kvzalloc(size_t size, unsigned int flags)
{
	expect_output_unpublished();
	expect(flags == GFP_KERNEL, "allocation occurs in process context");
	expect(size == sizeof(struct skp_group_paths_runtime), "allocation has real runtime size");
	++state.allocation_calls;
	if (state.fail_allocate == state.allocation_calls)
		return NULL;
	expect(!state.live_allocations, "one candidate owns one allocation");
	state.allocation = calloc(1, size);
	expect(state.allocation != NULL, "host fixture allocation succeeds");
	++state.live_allocations;
	return state.allocation;
}

void kvfree(const void *memory)
{
	expect_output_unpublished();
	expect(memory && memory == state.allocation, "free matches allocated candidate");
	expect(state.live_allocations == 1, "candidate is freed exactly once");
	expect_no_references();
	++state.free_calls;
	--state.live_allocations;
	free(state.allocation);
	state.allocation = NULL;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
	unsigned int i;

	expect_output_unpublished();
	expect(flags == LOOKUP_FOLLOW, "resolver follows the configured pathname");
	expect(path && !path->mnt && !path->dentry, "fresh path slot is zero initialized");
	++state.lookup_calls;
	if (state.gate_enabled && state.lookup_calls == 2) {
		expect(pthread_mutex_lock(&gate_mutex) == 0, "lock prepare gate");
		state.gate_entered = true;
		expect(pthread_cond_broadcast(&gate_condition) == 0, "announce paused lookup");
		while (!state.gate_release)
			expect(pthread_cond_wait(&gate_condition, &gate_mutex) == 0, "wait for preparation release");
		expect(pthread_mutex_unlock(&gate_mutex) == 0, "unlock prepare gate");
	}
	if (state.fail_lookup == state.lookup_calls)
		return -ENOENT;
	for (i = 0; i < fixture_count; ++i) {
		if (strcmp(name, fixtures[i].path))
			continue;
		path->mnt = &fixtures[i].mount;
		path->dentry = &fixtures[i].dentry;
		++path->mnt->references;
		++path->dentry->references;
		++state.paths_acquired;
		return 0;
	}
	return -ENOENT;
}

void path_put(const struct path *path)
{
	expect_output_unpublished();
	expect(path && path->mnt && path->dentry, "release only an acquired path");
	expect(path->mnt->references && path->dentry->references, "path has live references");
	--path->mnt->references;
	--path->dentry->references;
	++state.paths_released;
}

struct inode *d_inode(const struct dentry *dentry)
{
	expect_output_unpublished();
	expect(dentry && dentry->references, "inode read has held dentry");
	return dentry->inode;
}

struct inode *igrab(struct inode *inode)
{
	expect_output_unpublished();
	expect(inode != NULL, "igrab receives a live resolved inode");
	++state.grab_calls;
	if (state.fail_grab == state.grab_calls)
		return NULL;
	++inode->references;
	++state.inodes_acquired;
	return inode;
}

void iput(struct inode *inode)
{
	expect_output_unpublished();
	expect(inode && inode->references, "iput receives one held explicit reference");
	--inode->references;
	++state.inodes_released;
}

void spin_lock(struct runtime_test_spinlock *lock)
{
	expect_output_unpublished();
	expect(lock && !lock->locked, "dentry lock acquired once");
	lock->locked = true;
	++state.lock_calls;
}

void spin_unlock(struct runtime_test_spinlock *lock)
{
	expect_output_unpublished();
	expect(lock && lock->locked, "dentry lock released once");
	lock->locked = false;
	++state.unlock_calls;
}

long strscpy(char *destination, const char *source, size_t capacity)
{
	size_t length;

	expect_output_unpublished();
	expect(state.lock_calls == state.unlock_calls + 1, "basename read holds dentry lock");
	expect(destination && source && capacity == SKP_GROUP_PATH_LEN, "copy uses fixed bounded object name");
	for (length = 0; length + 1 < capacity && source[length]; ++length)
		destination[length] = source[length];
	destination[length] = 0;
	return source[length] ? -E2BIG : (long)length;
}

static struct skp_group_paths_config reset_case(unsigned int count)
{
	struct skp_group_paths_config config;
	unsigned int i;

	expect(!state.live_allocations, "previous case released allocation");
	memset(&state, 0, sizeof(state));
	memset(fixtures, 0, sizeof(fixtures));
	memset(&config, 0, sizeof(config));
	fixture_count = count;
	expect(count <= FIXTURES, "fixture count is bounded");
	config.version = SKP_GROUP_PATHS_VERSION;
	config.subjects.version = SKP_SUBJECT_POLICY_VERSION;
	config.subjects.facts_generation = 42;
	config.subjects.profile_count = 3;
	config.subjects.profiles[1] = 7;
	config.subjects.profiles[2] = 19;
	config.subjects.binding_count = 2;
	config.subjects.bindings[0].uid = 10101;
	config.subjects.bindings[0].profile_id = 7;
	config.subjects.bindings[1].uid = 10102;
	config.subjects.bindings[1].profile_id = 19;
	config.path_count = count;
	for (i = 0; i < count; ++i) {
		snprintf(fixtures[i].path, sizeof(fixtures[i].path), "/fixtures/path-%u", i);
		snprintf((char *)fixtures[i].basename, sizeof(fixtures[i].basename), "resolved-%u", i);
		fixtures[i].superblock.s_dev = 0x10000009U;
		fixtures[i].inode.i_sb = &fixtures[i].superblock;
		fixtures[i].inode.i_ino = 0x100000000ULL + i + 1;
		fixtures[i].initial_mode = 0100600U | (i & 077U);
		fixtures[i].inode.i_mode = fixtures[i].initial_mode;
		fixtures[i].dentry.inode = &fixtures[i].inode;
		fixtures[i].dentry.d_name.name = fixtures[i].basename;
		config.rules[i].profile_id = 7;
		strcpy(config.rules[i].path, fixtures[i].path);
	}
	return config;
}

static int prepare(struct skp_group_paths_config *config,
		   struct skp_group_paths_runtime **output)
{
	int result;

	/* A non-NULL sentinel proves production prepare clears the result before
	 * any failure or candidate work; no sentinel is ever dereferenced. */
	*output = (struct skp_group_paths_runtime *)(uintptr_t)1;
	state.watched_output = output;
	state.watch_output = true;
	result = skp_group_paths_runtime_prepare(config, output);
	state.watch_output = false;
	return result;
}

static void expect_failed(int result, int expected,
			  struct skp_group_paths_runtime *output)
{
	expect(result == expected, "fault returns the expected concrete errno");
	expect(output == NULL, "failed candidate is never returned");
	expect(!state.live_allocations, "failed candidate allocation is released");
	expect_no_references();
}

static void test_success_and_empty(void)
{
	struct skp_group_paths_config config = reset_case(2);
	struct skp_group_paths_runtime *runtime;
	struct skp_subject_context context = { 10101, 0, 0, 0, 0 };

	expect(prepare(&config, &runtime) == 0, "two-target resolver succeeds");
	expect(runtime && state.live_allocations == 1, "successful candidate remains owned by caller");
	expect(runtime->resolved_count == 2 && state.paths_acquired == 2 && state.inodes_acquired == 2,
	       "candidate holds every path and inode until readers are done");
	expect(memcmp(&runtime->config, &config, sizeof(config)) == 0, "candidate owns exact subject and rule snapshot");
	expect(runtime->objects[0].dev == 0x10000009ULL &&
	       runtime->objects[0].ino == 0x100000001ULL, "full width VFS identity is retained");
	expect(!strcmp(runtime->objects[0].name, "resolved-0"), "runtime captures actual dentry basename");
	expect(skp_group_paths_inode_hidden(&runtime->config, runtime->objects, 2,
	       &context, 0x10000009ULL, 0x100000001ULL), "actual prepared objects drive matching core");
	/* Caller storage may change after prepare: the candidate has no pointer
	 * back to incoming config or the caller's package-fact arrays. */
	config.subjects.bindings[0].profile_id = 19;
	config.rules[0].path[1] = 'X';
	expect(runtime->config.subjects.bindings[0].profile_id == 7 &&
	       runtime->config.rules[0].path[1] == 'f', "publication candidate is immutable with respect to caller edits");
	skp_group_paths_runtime_free(runtime);
	expect(state.free_calls == 1 && !state.live_allocations, "successful free releases candidate once");
	expect_no_references();
	config = reset_case(0);
	expect(prepare(&config, &runtime) == 0, "empty-rule candidate is valid");
	expect(runtime->resolved_count == 0 && state.lookup_calls == 0, "empty candidate performs no VFS lookup");
	skp_group_paths_runtime_free(runtime);
	expect_no_references();
	skp_group_paths_runtime_free(NULL);
	expect(state.free_calls == 1, "NULL release is harmless");
}

static void test_faults(void)
{
	struct skp_group_paths_config config = reset_case(2);
	struct skp_group_paths_runtime *runtime;
	int result;

	state.fail_allocate = 1;
	result = prepare(&config, &runtime);
	expect_failed(result, -ENOMEM, runtime);
	expect(state.lookup_calls == 0 && state.free_calls == 0, "allocation failure has no acquired resources");
	config = reset_case(2);
	state.fail_lookup = 2;
	result = prepare(&config, &runtime);
	expect_failed(result, -ENOENT, runtime);
	expect(state.paths_acquired == 1 && state.inodes_acquired == 1,
	       "second lookup failure unwinds prior complete target");
	config = reset_case(2);
	fixtures[1].dentry.inode = NULL;
	result = prepare(&config, &runtime);
	expect_failed(result, -ENOENT, runtime);
	expect(state.paths_acquired == 2 && state.inodes_acquired == 1,
	       "missing inode still releases the newly acquired path");
	config = reset_case(2);
	state.fail_grab = 2;
	result = prepare(&config, &runtime);
	expect_failed(result, -ESTALE, runtime);
	expect(state.paths_acquired == 2 && state.inodes_acquired == 1,
	       "failed igrab releases both paths and only held inode");
	config = reset_case(2);
	memset(fixtures[1].basename, 'x', SKP_GROUP_PATH_LEN);
	fixtures[1].basename[SKP_GROUP_PATH_LEN] = 0;
	result = prepare(&config, &runtime);
	expect_failed(result, -ENAMETOOLONG, runtime);
	expect(state.paths_acquired == 2 && state.inodes_acquired == 2 && state.unlock_calls == 2,
	       "overlong name releases both references and its dentry lock");
	config = reset_case(2);
	config.rules[0].path[0] = 'x';
	result = prepare(&config, &runtime);
	expect_failed(result, -EINVAL, runtime);
	expect(state.allocation_calls == 0 && state.lookup_calls == 0, "invalid config rejected before resource acquisition");
	config = reset_case(2);
	result = prepare(NULL, &runtime);
	expect_failed(result, -EINVAL, runtime);
	expect(skp_group_paths_runtime_prepare(&config, NULL) == -EINVAL, "NULL output rejected");
	expect(state.allocation_calls == 0, "NULL arguments never allocate");
}

static void test_aliases(void)
{
	struct skp_group_paths_config config = reset_case(2);
	struct skp_group_paths_runtime *runtime;
	struct skp_subject_context a = { 10101, 0, 0, 0, 0 };
	struct skp_subject_context b = { 10102, 0, 0, 0, 0 };
	int result;

	fixtures[1].dentry.inode = &fixtures[0].inode;
	result = prepare(&config, &runtime);
	expect_failed(result, -EEXIST, runtime);
	expect(state.paths_acquired == 2 && state.inodes_acquired == 2,
	       "same-profile alias rejected only after both targets were resolved");
	config = reset_case(2);
	fixtures[1].dentry.inode = &fixtures[0].inode;
	config.rules[1].profile_id = 19;
	expect(prepare(&config, &runtime) == 0, "different profiles may pin the same real inode");
	expect(fixtures[0].inode.references == 2 && fixtures[1].inode.references == 0,
	       "shared inode has independently held references");
	expect(runtime->objects[0].ino == runtime->objects[1].ino &&
	       runtime->objects[0].profile_id != runtime->objects[1].profile_id,
	       "same inode keeps distinct group metadata");
	expect(skp_group_paths_inode_hidden(&runtime->config, runtime->objects, 2,
	       &a, runtime->objects[0].dev, runtime->objects[0].ino), "A hides shared prepared inode");
	expect(skp_group_paths_inode_hidden(&runtime->config, runtime->objects, 2,
	       &b, runtime->objects[0].dev, runtime->objects[0].ino), "B hides shared prepared inode independently");
	skp_group_paths_runtime_free(runtime);
	expect_no_references();
}

struct prepare_thread {
	const struct skp_group_paths_config *config;
	struct skp_group_paths_runtime *output;
	int result;
};

static void *prepare_in_thread(void *argument)
{
	struct prepare_thread *thread = argument;

	thread->result = skp_group_paths_runtime_prepare(thread->config, &thread->output);
	return NULL;
}

static void test_not_published_during_preparation(void)
{
	struct skp_group_paths_config config = reset_case(2);
	struct prepare_thread thread = { &config, NULL, -1 };
	pthread_t worker;

	state.gate_enabled = true;
	state.watched_output = &thread.output;
	state.watch_output = true;
	expect(pthread_create(&worker, NULL, prepare_in_thread, &thread) == 0, "start real resolver thread");
	expect(pthread_mutex_lock(&gate_mutex) == 0, "lock observer gate");
	while (!state.gate_entered)
		expect(pthread_cond_wait(&gate_condition, &gate_mutex) == 0, "wait until second real kern_path is paused");
	expect(thread.output == NULL, "partially resolved candidate is not published");
	expect(state.live_allocations == 1 && state.paths_acquired == 1 && state.inodes_acquired == 1,
	       "paused candidate has actual partially held resources");
	state.gate_release = true;
	expect(pthread_cond_broadcast(&gate_condition) == 0, "release second path resolution");
	expect(pthread_mutex_unlock(&gate_mutex) == 0, "unlock observer gate");
	expect(pthread_join(worker, NULL) == 0, "join resolver after complete preparation");
	state.watch_output = false;
	expect(thread.result == 0 && thread.output && thread.output->resolved_count == 2,
	       "only complete candidate becomes caller-visible");
	skp_group_paths_runtime_free(thread.output);
	expect_no_references();
}

static void test_full_capacity_unwind(void)
{
	struct skp_group_paths_config config = reset_case(FIXTURES);
	struct skp_group_paths_runtime *runtime;
	int result;

	expect(prepare(&config, &runtime) == 0, "full 128-target runtime prepares");
	expect(runtime->resolved_count == FIXTURES && state.paths_acquired == FIXTURES &&
	       state.inodes_acquired == FIXTURES, "all capacity slots are pinned");
	skp_group_paths_runtime_free(runtime);
	expect_no_references();
	config = reset_case(FIXTURES);
	state.fail_grab = FIXTURES;
	result = prepare(&config, &runtime);
	expect_failed(result, -ESTALE, runtime);
	expect(state.paths_acquired == FIXTURES && state.inodes_acquired == FIXTURES - 1,
	       "last-slot fault unwinds maximum path count safely");
}

int main(void)
{
	test_success_and_empty();
	test_faults();
	test_aliases();
	test_not_published_during_preparation();
	test_full_capacity_unwind();
	printf("GROUP_PATHS_RUNTIME_HOST checks=%u passed=true kernel_calls=false production_source=true\n",
	       atomic_load_explicit(&checks, memory_order_relaxed));
	return 0;
}
