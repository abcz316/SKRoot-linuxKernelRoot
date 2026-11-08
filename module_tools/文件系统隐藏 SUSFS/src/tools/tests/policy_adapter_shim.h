/* SPDX-License-Identifier: GPL-2.0-only */
/* Included around exact extracted production functions, never device code. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <stddef.h>
#define SKP_POLICY_ADAPTER_HOSTTEST
#include "skp_policy_adapter.h"
#include "skp_group_objects_runtime.h"
#include "skp_full_objects_runtime.h"
#include "skp_mount_runtime.h"
struct skp_redirect_query_result {
 u32 matched, legacy_allowed; u64 generation;
 char path[SKP_GROUP_PATH_LEN], target_path[SKP_GROUP_PATH_LEN];
 u64 source_dev, source_ino, source_mnt_id; struct kstatfs source_statfs;
};
struct skp_group_mounts_runtime { struct skp_group_mount_object objects[SKP_GROUP_MOUNTS_MAX]; };
#define PROC_SUPER_MAGIC 0x9fa0UL
#define S_ISDIR(mode) (((mode) & 0170000) == 0040000)
#define __user
#define __rcu
#define U64_MAX UINT64_MAX
#define THIS_MODULE NULL
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
typedef long long loff_t;
struct file { void *private_data; };
struct seq_file { char text[4096]; size_t length; void *private; int (*show)(struct seq_file *, void *); };
struct task_struct { struct task_struct *group_leader; unsigned int refs; int exit_state; bool alive; };
static struct task_struct owner_a, owner_b, child_task, app_task;
static struct task_struct *current = &app_task;
static struct super_block proc_sb = { .s_dev = 450, .s_magic = PROC_SUPER_MAGIC };
static struct super_block other_sb = { .s_dev = 451, .s_magic = 0x1234 };
static struct inode proc_root = { .i_sb = &proc_sb, .i_ino = 1, .i_mode = 0040000 };
static struct inode proc_child = { .i_sb = &proc_sb, .i_ino = 2, .i_mode = 0040000 };
static struct inode other_root = { .i_sb = &other_sb, .i_ino = 1, .i_mode = 0040000 };

static u64 fake_boottime_ns = 1000000000ULL;
static u64 ktime_get_boottime_ns(void) { return fake_boottime_ns; }
static bool pid_alive(struct task_struct *task) { return task->alive; }
static void get_task_struct(struct task_struct *task) { ++task->refs; }
static void put_task_struct(struct task_struct *task) { if (!task->refs) abort(); --task->refs; }
struct list_head { struct list_head *next, *prev; };
static struct list_head manager_sessions = { &manager_sessions, &manager_sessions };
static struct runtime_test_spinlock manager_lock;
static unsigned int manager_count;
static u64 manager_session_sequence;
#define SKP_POLICY_MAX_MANAGERS 16U
#define list_for_each_entry_rcu(pos, head, member) \
 for (struct list_head *cursor = (head)->next; \
 cursor != (head) && ((pos) = (struct skp_policy_session *)((char *)cursor - offsetof(struct skp_policy_session, member)), 1); \
 cursor = cursor->next)
static void list_add_rcu(struct list_head *item, struct list_head *head) {
 item->next = head->next; item->prev = head; head->next->prev = item; head->next = item;
}
static void list_del_rcu(struct list_head *item) { item->prev->next = item->next; item->next->prev = item->prev; }
void spin_lock(struct runtime_test_spinlock *lock) { if (lock->locked) abort(); lock->locked = 1; }
void spin_unlock(struct runtime_test_spinlock *lock) { if (!lock->locked) abort(); lock->locked = 0; }
static int single_open(struct file *file, int (*show)(struct seq_file *, void *), void *private) {
 struct seq_file *stream = calloc(1, sizeof(*stream));
 if (!stream) return -ENOMEM;
 stream->private = private; stream->show = show; file->private_data = stream; return 0;
}
static int single_release(struct inode *inode, struct file *file) {
 (void)inode; free(file->private_data); file->private_data = NULL; return 0;
}
static ssize_t seq_read(struct file *file, char *buffer, size_t size, loff_t *position) {
 struct seq_file *stream = file->private_data; int result;
 if (*position == 0) { stream->length = 0; result = stream->show(stream, NULL); if (result) return result; }
 if ((size_t)*position >= stream->length) return 0;
 if (size > stream->length - (size_t)*position) size = stream->length - (size_t)*position;
 memcpy(buffer, stream->text + *position, size); *position += (loff_t)size; return (ssize_t)size;
}
struct mutex { int held; };
static struct mutex policy_write_lock;
static unsigned int checks, locks, rcu_depth, publications, graces, pins;
static unsigned int arm_paths, arm_kstats, arm_maps, arm_redirects, arm_mounts, prepares, frees;
static unsigned int temporary_frees, fail_redirect_arm, fail_mount_arm;
static bool fake_full_stable = true, fake_topology_stable = true;
static bool fail_second_stability;
static unsigned int stability_checks;
static unsigned int fail_pin, fail_arm, fail_prepare, race_prepare, fail_scope_alloc;
static u64 advance_during_prepare, advance_during_arm;
static struct task_struct *kill_during_prepare;
static unsigned int current_test_uid = 10001, manager;
static u64 policy_generation;
static bool policy_module_pinned;
static void expect(int ok, const char *message)
{
	++checks;
	if (!ok) { fprintf(stderr, "FAIL check=%u %s\n", checks, message); exit(1); }
}
static void mutex_lock(struct mutex *lock)
{
	expect(!lock->held && !locks, "policy lock outermost");
	lock->held = 1; locks = 1;
}
static void mutex_unlock(struct mutex *lock)
{
	expect(lock->held && locks == 1, "family locks released first");
	lock->held = 0; locks = 0;
}
#define lockdep_is_held(lock) ((lock)->held)
static void rcu_read_lock(void) { ++rcu_depth; }
static void rcu_read_unlock(void) { expect(rcu_depth >= 1, "balanced RCU guard"); --rcu_depth; }
#define rcu_dereference(p) ((void)expect(rcu_depth == 1, "single guarded pointer load"), (p))
#define rcu_dereference_protected(p, held) ((void)expect(held, "writer guard"), (p))
#define rcu_assign_pointer(p, value) do { expect(locks == 6, "publish under all writer locks"); if ((value) && (value)->full) expect(!(value)->full->temporary, "temporary refs detached before publication"); (p) = (value); publications++; } while (0)
static void synchronize_rcu(void) { expect(!rcu_depth && (locks == 6 || locks == 0), "drain snapshot or session before release"); ++graces; }
struct test_kuid { unsigned int val; };
static struct test_kuid current_uid(void)
{
	struct test_kuid result = { current_test_uid };
	return result;
}
static bool skp_policy_current_manager(void) { return manager != 0; }
static void *kzalloc(size_t size, unsigned int flags) { (void)flags; return calloc(1, size); }
void *kvzalloc(size_t size, unsigned int flags) { (void)flags; if (fail_scope_alloc) return NULL; return calloc(1, size); }
static void kfree(void *p) { expect(!locks, "snapshot release outside writer locks"); free(p); }
static void *vmemdup_user(const void *p, size_t n)
{
	void *out = malloc(n); expect(out != NULL, "host allocation"); memcpy(out, p, n); return out;
}
void kvfree(const void *p) { expect(!locks, "message free outside locks"); free((void *)p); }
static void *memchr_inv(const void *p, int byte, size_t n)
{
	const unsigned char *s = p;
	while (n--) { if (*s != (unsigned char)byte) return (void *)s; ++s; } return NULL;
}
static bool try_module_get(void *unused) { (void)unused; ++pins; return !fail_pin; }
static bool sus_path_group_supported(void) { return true; }
static unsigned int susfs_kstat_group_routes(void) { return 0x10007U; }
static unsigned int susfs_map_group_routes(void) { return 0x41U; }
static unsigned int susfs_open_redirect_group_routes(void) { return 0x7fU; }
static unsigned int susfs_mount_group_routes(void) { return 0x23U; }
static void seq_printf(struct seq_file *stream, const char *format, ...)
{
	int result;
	va_list arguments;
	va_start(arguments, format);
	result = vsnprintf(stream->text + stream->length,
			sizeof(stream->text) - stream->length, format, arguments);
	va_end(arguments);
	expect(result >= 0 && (size_t)result < sizeof(stream->text) - stream->length,
	       "whole production status fits seq buffer");
	stream->length += (size_t)result;
}
static void susfs_mount_group_write_begin(void) { expect(locks == 1, "mount guard outermost family"); locks = 2; }
static void sus_path_group_write_begin(void) { expect(locks == 2, "path lock order"); locks = 3; }
static void susfs_kstat_group_write_begin(void) { expect(locks == 3, "kstat lock order"); locks = 4; }
static void susfs_map_group_write_begin(void) { expect(locks == 4, "map lock order"); locks = 5; }
static void susfs_open_redirect_group_write_begin(void) { expect(locks == 5, "redirect lock order"); locks = 6; }
static void susfs_open_redirect_group_write_end(void) { expect(locks == 6, "redirect unlock order"); locks = 5; }
static void susfs_map_group_write_end(void) { expect(locks == 5, "map unlock order"); locks = 4; }
static void susfs_kstat_group_write_end(void) { expect(locks == 4, "kstat unlock order"); locks = 3; }
static void sus_path_group_write_end(void) { expect(locks == 3, "path unlock order"); locks = 2; }
static void susfs_mount_group_write_end(void) { expect(locks == 2, "mount guard released after path"); locks = 1; }
static int sus_path_group_arm_readlink_locked(struct inode *inode)
{
 (void)inode; expect(locks == 6, "arming after all locks"); ++arm_paths;
 return fail_arm ? -EBUSY : 0;
}
static int susfs_kstat_group_prepare_locked(void) { expect(locks == 6, "kstat arm lock"); ++arm_kstats; return 0; }
static int susfs_map_group_prepare_locked(void) { expect(locks == 6, "map arm lock"); ++arm_maps; return 0; }
static int susfs_open_redirect_group_prepare_locked(bool open)
{
 (void)open; expect(locks == 6, "redirect arm lock"); ++arm_redirects;
 if (advance_during_arm) { fake_boottime_ns += advance_during_arm; advance_during_arm = 0; }
 return fail_redirect_arm ? -EBUSY : 0;
}
static int susfs_mount_group_prepare_locked(void)
{
 expect(locks == 6, "mount arm lock"); ++arm_mounts;
 return fail_mount_arm ? -EBUSY : 0;
}

/* VFS preparation has separate production-resolver tests. Here a double
 * injects a second writer at the prepare/CAS boundary. No kernel concurrency
 * claim follows from this deterministic schedule. */
int skp_group_paths_runtime_prepare(const struct skp_group_paths_config *c,
		struct skp_group_paths_runtime **out)
{
	expect(!locks && !rcu_depth, "resolver outside all writer locks");
	++prepares;
	*out = calloc(1, sizeof(**out));
	expect(*out != NULL, "host path allocation");
	(*out)->config = *c;
	for (unsigned int i = 0; i < c->path_count; ++i) {
	 (*out)->objects[i].profile_id = c->rules[i].profile_id;
	 (*out)->objects[i].dev = 123; (*out)->objects[i].ino = 456;
	 strcpy((*out)->objects[i].name, "fixture");
	 if (!strcmp(c->rules[i].path, "/fixture/proc-alias")) (*out)->inodes[i] = &proc_root;
	 if (!strcmp(c->rules[i].path, "/fixture/proc-child")) (*out)->inodes[i] = &proc_child;
	 if (!strcmp(c->rules[i].path, "/fixture/other-root")) (*out)->inodes[i] = &other_root;
	}
	if (advance_during_prepare) { fake_boottime_ns += advance_during_prepare; advance_during_prepare = 0; }
	if (kill_during_prepare) { kill_during_prepare->exit_state = 1; kill_during_prepare = NULL; }
	if (race_prepare) { ++policy_generation; race_prepare = 0; }
	return 0;
}
void skp_group_paths_runtime_free(struct skp_group_paths_runtime *runtime)
{
	expect(!locks, "path/inode release outside locks");
	if (runtime) { ++frees; free(runtime); }
}
int skp_group_objects_runtime_prepare(const struct skp_group_objects_config *c,
		struct skp_group_objects_runtime **out)
{
	int result;
	expect(!locks && !rcu_depth, "complete resolver outside writer/RCU locks");
	if (fail_prepare) return -ENOENT;
	*out = calloc(1, sizeof(**out)); expect(*out != NULL, "host objects allocation");
	(*out)->config = *c;
	result = skp_group_paths_runtime_prepare(&c->paths, &(*out)->paths);
	(*out)->kstats[0].dev = (*out)->maps[0].dev = 123;
	(*out)->kstats[0].ino = (*out)->maps[0].ino = 456;
 for (unsigned int i = 0; i < c->kstat_count; ++i) {
  (*out)->kstats[i].profile_id = c->kstats[i].profile_id;
  (*out)->kstats[i].dev = 123;
  (*out)->kstats[i].ino = !strcmp(c->kstats[i].path,"/fixture/target") ? 790 : 456;
 }
	return result;
}
void skp_group_objects_runtime_free(struct skp_group_objects_runtime *runtime)
{
	expect(!locks, "complete refs release outside locks");
	if (runtime) { skp_group_paths_runtime_free(runtime->paths); free(runtime); }
}

void skp_redirect_prepare_refs_free(struct skp_redirect_prepare_refs *refs)
{
 expect(!locks && !rcu_depth, "temporary mount refs released outside guards");
 if (refs) { ++temporary_frees; free(refs); }
}
bool skp_group_mounts_runtime_stable(const struct skp_group_mounts_runtime *runtime)
{
 (void)runtime; return fake_topology_stable;
}
const struct skp_group_mount_object *skp_group_mounts_objects(const struct skp_group_mounts_runtime *runtime)
{
 return runtime ? runtime->objects : NULL;
}
bool skp_full_objects_runtime_stable(const struct skp_full_objects_runtime *runtime)
{
 (void)runtime; expect(locks == 6, "final candidate stability inside all writer locks");
 ++stability_checks;
 return fake_full_stable && !(fail_second_stability && stability_checks == 2);
}
int skp_full_objects_runtime_prepare(const struct skp_full_objects_config *c,
        struct skp_full_objects_runtime **out)
{
 unsigned int i; int result;
 expect(!locks && !rcu_depth, "full resolver outside all guards");
 if (fail_prepare) return -ENOENT;
 *out = calloc(1, sizeof(**out)); expect(*out != NULL, "host full allocation");
 (*out)->config = *c;
 result = skp_group_objects_runtime_prepare(&c->objects, &(*out)->objects);
 if (result) return result;
 (*out)->temporary = calloc(1, sizeof(*(*out)->temporary));
 (*out)->mounts = calloc(1, sizeof(*(*out)->mounts));
 expect((*out)->temporary && (*out)->mounts, "host temporary and mount allocation");
 for (i = 0; i < c->redirect_count; ++i) {
  struct skp_group_redirect_object *r = &(*out)->redirects[i];
  r->profile_id = c->redirects[i].profile_id;
  r->source.dev = r->target.dev = 123;
  r->source.ino = 789 + i * 2; r->target.ino = 790 + i * 2;
  r->source.igen = 3; r->target.igen = 4;
  r->source_mnt_id = 31; r->target_mnt_id = 32;
  (*out)->source_statfs[i].f_type = 0x1234;
 }
 for (i = 0; i < c->mount_count; ++i) {
  struct skp_group_mount_object *m = &(*out)->mounts->objects[i];
  m->profile_id = c->mounts[i].profile_id; m->chain_count = 2;
  m->cookies[0] = 1031 + i; m->ids[0] = 31 + i;
  m->cookies[1] = 1001; m->ids[1] = 1;
 }
 return 0;
}
void skp_full_objects_runtime_free(struct skp_full_objects_runtime *runtime)
{
 expect(!locks && !rcu_depth, "full snapshot refs released outside all guards");
 if (runtime) {
  skp_group_objects_runtime_free(runtime->objects);
  skp_redirect_prepare_refs_free(runtime->temporary);
  free(runtime->mounts); free(runtime);
 }
}
