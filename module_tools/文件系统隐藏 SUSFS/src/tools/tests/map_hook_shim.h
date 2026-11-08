/* SPDX-License-Identifier: GPL-2.0-only */
/* Typed host boundaries; production bodies are inserted by map_hook_regression.py. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "skp_group_objects.h"
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned int dev_t;
typedef struct { unsigned int val; } kuid_t;
typedef struct { int value; } atomic_t;
#define PAGE_SIZE 4096
#define SUS_MAP_MAX 64
#define GFP_ATOMIC 1
#define LOOKUP_FOLLOW 1
#define TWA_RESUME 1
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define __user
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define smp_load_acquire(pointer) (*(pointer))
#define smp_store_release(pointer, value) (*(pointer) = (value))
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
static unsigned int checks;
static void expect(bool condition, const char *message)
{
    checks++;
    if (!condition) { fprintf(stderr, "FAIL check=%u: %s\n", checks, message); exit(1); }
}
struct test_lock { bool held; };
static struct test_lock map_ctl_lock, map_table_lock;
static void mutex_lock(struct test_lock *lock) { expect(!lock->held, "no recursive writer lock"); lock->held = true; }
static void mutex_unlock(struct test_lock *lock) { expect(lock->held, "unlock owns mutex"); lock->held = false; }
#define lockdep_assert_held(lock) expect((lock)->held, "production prepare/writer holds map mutex")
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; mutex_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); mutex_unlock(lock); } while (0)
static void atomic_inc(atomic_t *counter) { counter->value++; }
static int atomic_dec_if_positive(atomic_t *counter)
{
    if (counter->value <= 0) return -1;
    return --counter->value;
}
static void log_discard(const char *format, ...) { (void)format; }
#define SUSFS_LOGI log_discard
#define pr_warn log_discard
#define pr_info_ratelimited log_discard
struct super_block { dev_t s_dev; };
struct inode { unsigned long i_ino; struct super_block *i_sb; };
struct file { struct inode *inode; };
struct dentry { struct inode *inode; };
struct path { struct dentry *dentry; };
struct vm_area_struct {
    unsigned long vm_start, vm_end;
    struct file *vm_file;
    struct vm_area_struct *vm_next;
};
struct mm_struct { struct vm_area_struct *mmap; unsigned int owner_uid; };
struct test_vma_iterator { struct vm_area_struct *next; };
#define VMA_ITERATOR(name, mm, start) struct test_vma_iterator name = { (mm)->mmap }; (void)(start)
#define for_each_vma(iterator, vma) \
    for (; ((vma) = (iterator).next) != NULL; (iterator).next = (vma)->vm_next)
struct pt_regs { unsigned long regs[31]; unsigned long pc; };
struct kprobe { const char *symbol_name; int (*pre_handler)(struct kprobe *, struct pt_regs *); void *addr; };
struct kretprobe_instance { unsigned long data[1]; };
struct kretprobe {
    struct kprobe kp;
    int (*entry_handler)(struct kretprobe_instance *, struct pt_regs *);
    int (*handler)(struct kretprobe_instance *, struct pt_regs *);
    size_t data_size;
    int maxactive;
};
struct callback_head { void (*func)(struct callback_head *); };
struct kernel_param { unsigned long *arg; };
struct st_susfs_sus_map { char target_pathname[256]; int err; };
static struct inode *file_inode(struct file *file) { return file->inode; }
static struct inode *d_inode(struct dentry *dentry) { return dentry->inode; }
static struct inode *d_backing_inode(struct dentry *dentry) { return dentry->inode; }
static unsigned long regs_return_value(struct pt_regs *regs) { return regs->regs[0]; }
static void regs_set_return_value(struct pt_regs *regs, unsigned long value) { regs->regs[0] = value; }
/* PRODUCTION_STRUCTURES_AND_PROBES */
#define N_MAP_PROBES ARRAY_SIZE(map_probes)
static struct sus_map_entry map_entries[SUS_MAP_MAX];
static int nmap;
static bool map_probe_armed[N_MAP_PROBES], map_registered, kr_map_files_ok, map_ready;
static const void *sus_map_ops_smaps, *sus_map_ops_smaps_shmem, *sus_map_ops_pagemap;
static bool sus_map_walk_ops_done;
static int walk_dbg;
static atomic_t n_walk_skip, n_walk_seen, n_walk_seen_vma, n_walk_ops_hit;
static atomic_t n_walk_scan_fail, n_walk_nofile, n_walk_nomatch, n_walk_dbg_left;
static atomic_t n_map_files_hides, n_map_files_putfail, n_getlink_calls;
static atomic_t n_getlink_skip, n_getlink_nomatch, n_gup_calls, n_gup_inner_calls, n_vm_hides;
static unsigned int reader_uid = 10101;
static unsigned int query_calls, upstream_calls;
static bool upstream_allowed, grouped_hidden, legacy_allowed, group_active;
static enum skp_object_query_mode query_mode;
static u64 expected_dev, expected_ino;
static unsigned int expected_reader;
static bool copy_failure, malloc_failure, task_failure, in_probe;
static unsigned int allocations, frees, path_refs, path_puts;
static struct callback_head *queued_work;
static int current_token;
#define current (&current_token)
static struct path resolved_path;
static int resolution_error;
static unsigned int resolve_calls;
static bool takeover_during_resolve;
static unsigned int fail_probe_mask, attempts[N_MAP_PROBES + 1], resolved_ops_mask;
static unsigned int marker_smaps, marker_shmem, marker_pagemap;
static kuid_t current_uid(void) { kuid_t uid = { reader_uid }; return uid; }
static bool susfs_is_current_proc_umounted_app(void) { upstream_calls++; return upstream_allowed; }
static bool skp_policy_paths_active(void) { return group_active; }
static enum skp_object_query_mode skp_policy_map_query(u64 dev, u64 ino, struct skp_map_query_result *result)
{
    query_calls++;
    expect(reader_uid == expected_reader, "query uses current reader, never target mm owner");
    expect(dev == expected_dev && ino == expected_ino, "query uses exact raw device and inode");
    memset(result, 0, sizeof(*result));
    result->hidden = grouped_hidden; result->legacy_allowed = legacy_allowed;
    result->generation = query_calls;
    return query_mode;
}
static void sus_map_note_ops(const void *ops) { (void)ops; }
static void *find_kernel_symbol_exact(const char *name)
{
    if (!strcmp(name, "smaps_walk_ops")) return (resolved_ops_mask & 1) ? &marker_smaps : NULL;
    if (!strcmp(name, "smaps_shmem_walk_ops")) return (resolved_ops_mask & 2) ? &marker_shmem : NULL;
    if (!strcmp(name, "pagemap_ops")) return (resolved_ops_mask & 4) ? &marker_pagemap : NULL;
    expect(false, "only documented walk ops symbols resolved"); return NULL;
}
static int register_kprobe(struct kprobe *probe)
{
    size_t index;
    expect(map_ctl_lock.held, "probe registration serialized with publication");
    for (index = 0; index < N_MAP_PROBES && map_probes[index] != probe; index++) { }
    expect(index < N_MAP_PROBES && !probe->addr, "known probe registers with clear resolved address");
    attempts[index]++; probe->addr = probe;
    return (fail_probe_mask & (1U << index)) ? -ENOENT : 0;
}
static int register_kretprobe(struct kretprobe *probe)
{
    expect(map_ctl_lock.held && probe == &kr_map_files && !probe->kp.addr, "known map_files probe has serialized clear address");
    attempts[N_MAP_PROBES]++; probe->kp.addr = probe;
    return (fail_probe_mask & (1U << N_MAP_PROBES)) ? -ENOENT : 0;
}
static void susfs_kp_forget_addr(struct kprobe *probe) { probe->addr = NULL; }
static void susfs_krp_forget_addr(struct kretprobe *probe) { probe->kp.addr = NULL; }
static void *kmalloc(size_t size, int flags)
{
    expect(flags == GFP_ATOMIC && in_probe, "map_files allocation uses non-sleeping probe context");
    if (malloc_failure) return NULL;
    allocations++; return malloc(size);
}
static void kfree(void *pointer) { expect(pointer != NULL, "free owns allocation"); frees++; free(pointer); }
static void init_task_work(struct callback_head *callback, void (*fn)(struct callback_head *)) { callback->func = fn; }
static int task_work_add(void *task, struct callback_head *callback, int resume)
{
    expect(task == current && resume == TWA_RESUME && in_probe, "deferred release belongs to current reader");
    if (task_failure) return -ESRCH;
    expect(queued_work == NULL, "fixture has one queued reference transfer"); queued_work = callback; return 0;
}
static void path_put(const struct path *path)
{
    expect(!in_probe && !map_ctl_lock.held && path->dentry != NULL && path_refs > 0,
           "path release is sleepable, outside writer lock, with owned reference");
    path_refs--; path_puts++;
}
static int kern_path(const char *name, int flags, struct path *path)
{
    expect(!map_ctl_lock.held && flags == LOOKUP_FOLLOW && !strcmp(name, "/fixture"), "resolve outside publication lock");
    resolve_calls++;
    if (takeover_during_resolve) group_active = true;
    if (resolution_error) return resolution_error;
    *path = resolved_path; path_refs++; return 0;
}
static size_t copy_from_user(void *destination, const void *source, size_t size)
{
    if (copy_failure) return 1;
    memcpy(destination, source, size); return 0;
}
static size_t copy_to_user(void *destination, const void *source, size_t size) { memcpy(destination, source, size); return 0; }
static bool susfs_abi_path_ok(const char *path, size_t size) { return memchr(path, 0, size) != NULL; }
static int param_set_ulong(const char *value, const struct kernel_param *parameter)
{
    char *end;
    unsigned long parsed;
    expect(!map_ready || map_ctl_lock.held, "live parameter publication holds writer mutex; pre-init is storage-only");
    parsed = strtoul(value, &end, 0); if (*end) return -EINVAL;
    *parameter->arg = parsed; return 0;
}
#define find_vma sus_map_find_vma
/* PRODUCTION_FUNCTIONS */

static struct super_block fixture_sb = { 259 }, alternate_sb = { 260 };
static struct inode fixture_inode = { 41, &fixture_sb }, alternate_inode = { 42, &alternate_sb };
static struct file fixture_file = { &fixture_inode }, no_inode_file;
static struct dentry fixture_dentry = { &fixture_inode }, empty_dentry;
static struct vm_area_struct fixture_vma = { 0x4000, 0x6000, &fixture_file, NULL };
static struct mm_struct fixture_mm = { &fixture_vma, 99999 };
static void reset(void)
{
    size_t index;
    expect(!map_ctl_lock.held && !map_table_lock.held && queued_work == NULL && allocations == frees && !path_refs,
           "previous fixture releases all references, work, allocation and locks");
    memset(map_entries, 0, sizeof(map_entries)); nmap = 0;
    query_calls = upstream_calls = 0; reader_uid = expected_reader = 10101;
    query_mode = SKP_OBJECT_GROUPED; grouped_hidden = true; legacy_allowed = true;
    upstream_allowed = false; group_active = true; expected_dev = fixture_sb.s_dev; expected_ino = fixture_inode.i_ino;
    copy_failure = malloc_failure = task_failure = in_probe = takeover_during_resolve = false;
    allocations = frees = path_puts = resolve_calls = 0; resolution_error = 0;
    resolved_path.dentry = &fixture_dentry;
    fixture_file.inode = &fixture_inode; fixture_vma.vm_file = &fixture_file;
    fixture_mm.mmap = &fixture_vma; fixture_vma.vm_next = NULL;
    sus_map_ops_smaps = &marker_smaps; sus_map_ops_smaps_shmem = &marker_shmem; sus_map_ops_pagemap = &marker_pagemap;
    sus_map_walk_ops_done = false; resolved_ops_mask = 7; fail_probe_mask = 0;
    map_registered = kr_map_files_ok = false; map_ready = true;
    memset(map_probe_armed, 0, sizeof(map_probe_armed)); memset(attempts, 0, sizeof(attempts));
    for (index = 0; index < N_MAP_PROBES; index++) map_probes[index]->addr = NULL;
    kr_map_files.kp.addr = NULL;
}
static struct pt_regs registers(void)
{
    struct pt_regs regs = { { 0 }, 0x1234 };
    regs.regs[30] = 0x5678; return regs;
}
static void drain(void)
{
    struct callback_head *work = queued_work;
    expect(!in_probe, "callback drains after probe returns");
    queued_work = NULL; if (work) work->func(work);
}
static bool route(unsigned int index)
{
    struct pt_regs regs = registers();
    struct kretprobe_instance ri = { { 0 } };
    struct path path = { &fixture_dentry };
    int result;
    if (index == 0) {
        regs.regs[1] = (unsigned long)&fixture_vma;
        result = sus_map_skip_vma_pre(&kp_map, &regs);
    } else if (index == 1) {
        regs.regs[0] = (unsigned long)&fixture_mm; regs.regs[1] = 0x4000; regs.regs[3] = (unsigned long)&marker_smaps;
        result = sus_map_skip_walk_pre(&kp_map_walk, &regs);
    } else if (index == 2) {
        regs.regs[0] = (unsigned long)&fixture_vma; regs.regs[1] = (unsigned long)&marker_pagemap;
        result = sus_map_skip_walk_vma_pre(&kp_map_walk_vma, &regs);
    } else if (index == 3) {
        regs.regs[0] = (unsigned long)&fixture_mm; regs.regs[1] = 0x4000;
        result = sus_map_vm_access_pre(&kp_gup_remote, &regs);
    } else {
        regs.regs[1] = (unsigned long)&path; sus_map_maplink_entry(&ri, &regs); regs.regs[0] = 0;
        path_refs++; in_probe = true; result = sus_map_maplink_ret(&ri, &regs); in_probe = false;
        expect(result == 0, "kretprobe callback preserves handler return convention");
        if ((long)regs.regs[0] == -ENOENT) {
            expect(queued_work && path_refs == 1, "ENOENT transfers caller path reference to deferred work"); drain(); return true;
        }
        expect(regs.regs[0] == 0 && !queued_work, "non-hidden map_files retains original caller-owned reference");
        path_put(&path); return false;
    }
    if (result) expect(regs.pc == regs.regs[30] && regs.regs[0] == 0, "hidden route returns zero and skips to LR");
    else expect(regs.pc == 0x1234, "visible route preserves original execution");
    return result != 0;
}
static void test_modes_and_zero_legacy(void)
{
    unsigned int index;
    for (index = 0; index < 5; index++) {
        reset(); expect(route(index), "every grouped route works with zero legacy count");
        expect(query_calls == 1 && !upstream_calls, "one authoritative reader/object query, no upstream gate");
        expect(allocations == frees && !path_refs, "route leaves no reference/allocation");
        grouped_hidden = false; map_entries[0].target_dev = fixture_sb.s_dev; map_entries[0].target_ino = fixture_inode.i_ino; nmap = 1;
        expect(!route(index), "grouped miss/exempt never borrows positive legacy table");
        query_mode = SKP_OBJECT_LEGACY_SUBJECT; legacy_allowed = false; upstream_allowed = true;
        expect(!route(index), "subject-only denial never falls back to upstream gate");
        legacy_allowed = true; upstream_allowed = false;
        expect(route(index), "subject-only allowed uses legacy table without upstream predicate");
        query_mode = SKP_OBJECT_UPSTREAM;
        expect(!route(index), "upstream denial preserves visibility despite old table");
        upstream_allowed = true; expect(route(index), "upstream positive keeps existing object table behavior");
        reader_uid = expected_reader = 0; query_mode = SKP_OBJECT_GROUPED; grouped_hidden = false;
        expect(!route(index), "reader exemption is authoritative despite target mm owning an app UID");
    }
    reset(); query_mode = SKP_OBJECT_UPSTREAM; upstream_allowed = true;
    map_entries[0].target_ino = fixture_inode.i_ino; nmap = 1;
    expect(route(0), "upstream map_ino wildcard remains legacy-only");
    map_entries[0].target_dev = alternate_sb.s_dev;
    expect(!route(0), "legacy exact rule does not cross filesystem device");
}
static void test_invalid_vmas_walk_ops_and_gap(void)
{
    struct pt_regs regs;
    reset(); regs = registers(); regs.regs[1] = 1;
    expect(sus_map_skip_vma_pre(&kp_map_smap, &regs) == 0 && query_calls == 0, "sentinel never dereferences a VMA or selects a group");
    fixture_vma.vm_file = NULL; expect(!route(0) && !route(1) && !route(2) && !route(3), "anonymous VMA never hides");
    fixture_vma.vm_file = &no_inode_file; expect(!route(0) && !route(1) && !route(2) && !route(3), "missing inode never matches");
    fixture_vma.vm_file = &fixture_file; regs = registers(); regs.regs[0] = 1; regs.regs[1] = (unsigned long)&marker_smaps;
    expect(!sus_map_skip_walk_vma_pre(&kp_map_walk_vma, &regs), "walk-vma sentinel is defended too");
    regs = registers(); regs.regs[3] = (unsigned long)&alternate_inode; regs.regs[0] = 1;
    expect(!sus_map_skip_walk_pre(&kp_map_walk, &regs) && !query_calls, "unverified walk ops return before mm dereference");
    regs = registers(); regs.regs[0] = (unsigned long)&fixture_vma; regs.regs[1] = (unsigned long)&alternate_inode;
    expect(!sus_map_skip_walk_vma_pre(&kp_map_walk_vma, &regs) && !query_calls, "walk-vma only observes verified ops");
    regs = registers(); regs.regs[0] = (unsigned long)&fixture_mm; regs.regs[1] = 0x3000; regs.regs[3] = (unsigned long)&marker_shmem;
    expect(!sus_map_skip_walk_pre(&kp_map_walk, &regs) && !query_calls, "page-range gap never borrows the next hidden VMA");
    expect(!sus_map_vm_access_pre(&kp_gup_remote, &regs) && !query_calls, "remote gap never borrows next hidden mapping");
    regs.regs[1] = 0x6000; expect(!sus_map_vm_access_pre(&kp_gup_remote_inner, &regs), "remote address at exclusive end is outside mapping");
    regs.regs[1] = 0x4000; expect(sus_map_vm_access_pre(&kp_gup_remote_inner, &regs) == 1 && query_calls == 1, "inner remote route shares exact group answer");
    regs = registers(); regs.regs[1] = (unsigned long)&fixture_vma;
    expect(sus_map_skip_vma_pre(&kp_map_smap, &regs) == 1, "smaps listing shares grouped selection with maps");
}
static void test_maplink_reference_failures(void)
{
    struct pt_regs regs;
    struct kretprobe_instance ri;
    struct path path;
    unsigned int hides;
    reset(); regs = registers(); path.dentry = &fixture_dentry; regs.regs[1] = (unsigned long)&path;
    sus_map_maplink_entry(&ri, &regs); regs.regs[0] = (unsigned long)-EACCES; in_probe = true;
    expect(sus_map_maplink_ret(&ri, &regs) == 0 && (long)regs.regs[0] == -EACCES && !query_calls && !queued_work,
           "original map_files failure is untouched without reading output path"); in_probe = false;
    regs.regs[0] = 0; ri.data[0] = 0; expect(!sus_map_maplink_ret(&ri, &regs) && !query_calls, "null output pointer is untouched");
    ri.data[0] = (unsigned long)&path; path.dentry = NULL; expect(!sus_map_maplink_ret(&ri, &regs) && !query_calls, "null dentry is untouched");
    path.dentry = &empty_dentry; expect(!sus_map_maplink_ret(&ri, &regs) && !query_calls, "negative dentry is untouched");
    hides = (unsigned int)n_map_files_hides.value; malloc_failure = true;
    expect(!route(4) && !allocations && !queued_work && !path_refs, "allocation failure leaves original success and caller frees reference");
    expect((unsigned int)n_map_files_hides.value == hides, "failed reference transfer is not counted as hidden");
    malloc_failure = false; task_failure = true;
    expect(!route(4) && allocations == frees && !queued_work && !path_refs, "queue failure frees work but retains caller ownership");
    task_failure = false; expect(route(4) && allocations == frees && !path_refs, "successful deferred release drains exactly once");
}
static void test_group_arming(void)
{
    size_t index;
    reset(); susfs_map_group_write_begin();
    expect(susfs_map_group_prepare_locked() == 0 && nmap == 0, "first grouped publish arms routes without legacy rule mutation");
    expect(susfs_map_group_routes() == 1023, "route mask reports all six probes, map_files and three resolved walk ops");
    for (index = 0; index < N_MAP_PROBES + 1; index++) expect(attempts[index] == 1, "each route armed once");
    expect(!susfs_map_group_prepare_locked(), "repeat prepare remains optional-success");
    for (index = 0; index < N_MAP_PROBES + 1; index++) expect(attempts[index] == 1, "already armed routes are not double registered");
    susfs_map_group_write_end();
    reset(); fail_probe_mask = (1U << 0) | (1U << 3) | (1U << 6); susfs_map_group_write_begin();
    expect(!susfs_map_group_prepare_locked(), "missing primary and optional routes degrade without rejecting grouped publication");
    expect(susfs_map_group_routes() == (1023U & ~fail_probe_mask), "failed route bits are absent independently of primary");
    expect(!map_probes[0]->addr && !map_probes[3]->addr && !kr_map_files.kp.addr, "failed arm clears resolved address for safe retry");
    fail_probe_mask = 0; expect(!susfs_map_group_prepare_locked() && susfs_map_group_routes() == 1023, "retry can arm missing routes");
    expect(attempts[0] == 2 && attempts[3] == 2 && attempts[6] == 2 && attempts[1] == 1, "retry only attempts missing routes");
    susfs_map_group_write_end();
    reset(); resolved_ops_mask = 0; susfs_map_group_write_begin(); expect(!susfs_map_group_prepare_locked(), "missing walk ops degrade");
    expect(susfs_map_group_routes() == (127U & ~(1U << 2) & ~(1U << 3)), "no walk ops means no unsafe global walk hook");
    expect(!attempts[2] && !attempts[3], "unverified page walkers are never armed"); susfs_map_group_write_end();
}
static void test_legacy_writer_guards(void)
{
    struct st_susfs_sus_map request;
    void *pointer = &request;
    unsigned long param = 7;
    struct kernel_param kp = { &param };
    reset(); memset(&request, 0, sizeof(request)); strcpy(request.target_pathname, "/fixture");
    map_ready = false; map_ctl_lock.held = true;
    expect(!sus_map_ino_set("13", &kp) && param == 13 && map_ctl_lock.held,
           "pre-init parameter stores value without locking or consulting active grouped policy");
    map_ctl_lock.held = false; map_ready = true; param = 7;
    susfs_sus_map_supercall(&pointer);
    expect(request.err == -EBUSY && !nmap && !path_refs && resolve_calls == 1, "grouped mode rejects legacy resolved write and releases candidate outside lock");
    expect(sus_map_ino_set("99", &kp) == -EBUSY && param == 7, "grouped mode rejects mutable wildcard parameter");
    group_active = false; expect(!sus_map_ino_set("99", &kp) && param == 99, "legacy parameter keeps original storage behavior");
    expect(sus_map_ino_set("invalid", &kp) == -EINVAL && param == 99, "invalid parameter preserves old value");
    takeover_during_resolve = true; susfs_sus_map_supercall(&pointer);
    expect(request.err == -EBUSY && !nmap && !path_refs, "legacy writer rechecks takeover after slow resolve");
    group_active = takeover_during_resolve = false; susfs_sus_map_supercall(&pointer);
    expect(!request.err && nmap == 1 && !path_refs && map_entries[0].target_dev == fixture_sb.s_dev && map_registered,
           "legacy add publishes exact identity and arms with one serialized transaction");
    resolution_error = -ENOENT; susfs_sus_map_supercall(&pointer);
    expect(request.err == -ENOENT && nmap == 1 && !path_refs, "resolution failure leaves old legacy table untouched");
    resolution_error = 0; nmap = SUS_MAP_MAX; susfs_sus_map_supercall(&pointer);
    expect(request.err == -ENOSPC && nmap == SUS_MAP_MAX && !path_refs, "full legacy table fails without reference leak");
    copy_failure = true; susfs_sus_map_supercall(&pointer); expect(request.err == -EFAULT && !path_refs, "copy fault never resolves or mutates");
    copy_failure = false; memset(request.target_pathname, 'x', sizeof(request.target_pathname)); susfs_sus_map_supercall(&pointer);
    expect(request.err == -ENAMETOOLONG && !path_refs, "unterminated path fails before VFS");
}
int main(void)
{
    test_modes_and_zero_legacy(); test_invalid_vmas_walk_ops_and_gap();
    test_maplink_reference_failures(); test_group_arming(); test_legacy_writer_guards();
    expect(!queued_work && !path_refs && allocations == frees && !map_ctl_lock.held, "final fixture owns no test resources");
    printf("MAP_HOOK_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n", checks);
    return 0;
}
