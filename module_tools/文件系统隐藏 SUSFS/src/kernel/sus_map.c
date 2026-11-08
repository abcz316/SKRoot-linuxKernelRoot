// SPDX-License-Identifier: GPL-2.0
/*
 * sus_map.c - hide mmapped real files from /proc/<pid>/maps (SUSFS SUS_MAP).
 *
 * Upstream sets AS_FLAGS_SUS_MAP on the inode's address_space and makes
 * show_map_vma()/show_smap() skip the line, the smaps_rollup() loop skip the vma it
 * accumulates and pagemap_read() skip the chunk covering such a vma.  An LKM cannot add a
 * flag bit, so: a listing layer (kprobes on show_map_vma/show_smap, vma = regs->regs[1],
 * skip the line with regs->pc = x30) plus a page-walk layer for the two listings it cannot
 * reach (smaps_rollup, pagemap).  smaps_rollup is deliberately NOT probed directly (see
 * "the sentinel") and the skip is gated like upstream's, apps only (see "the read gate").
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>		/* struct mm_struct; sus_map_find_vma() walks its vmas */
#include <linux/mm_types.h>
#include <linux/version.h>	/* LINUX_VERSION_CODE: mm->mmap vs mm->mm_mt (6.1) */
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/err.h>		/* IS_ERR/ERR_PTR for the getlink hook */
#include <linux/cred.h>		/* current_uid(), for the read gate */
#include <linux/spinlock.h>	/* serialises rule publication */
#include <linux/slab.h>		/* kmalloc(GFP_ATOMIC), for the deferred path release */
#include <linux/task_work.h>	/* the map_files reference is released from task_work */
#include <linux/mutex.h>	/* map_ctl_lock: serialises probe arming */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact, for the walk ops */
#include "ksu_umount_gate.h"	/* susfs_is_current_proc_umounted_app (issue #34) */
#include "skp_policy_adapter.h"
#include "susfs_kprobe.h"

#define SUS_MAP_MAX 64

struct sus_map_entry {
    unsigned long target_ino;
    dev_t target_dev;
};

static struct sus_map_entry map_entries[SUS_MAP_MAX];
static int nmap;

/* Serialises rule PUBLICATION only; the reader stays lock-free: entries are append-only
 * (kstat's are replaced wholesale, hence its reader-side snapshot), so a release/acquire
 * pair on nmap publishes a filled entry or none - and it has to be that on arm64, where
 * plain WRITE_ONCE/READ_ONCE could publish the count first.  The lock itself is for two
 * concurrent supercalls (each in its own task_work), which would otherwise fill one slot
 * and silently drop a rule while both report success. */
static DEFINE_SPINLOCK(map_table_lock);
/* Order: policy -> path -> kstat -> map. Resolution/ref release is outside. */
static DEFINE_MUTEX(map_ctl_lock);

/* temporary interface: insmod susfs_guard_lkm.ko map_ino=<n> hides that inode */
static unsigned long param_map_ino;
static bool map_ready;
static int sus_map_ino_set(const char *value, const struct kernel_param *kp)
{
    int rc;

    /* parse_args precedes susfs_imports_guard. Before init only store the
     * insmod parameter; do not enter live mutex/RCU machinery yet. */
    if (!READ_ONCE(map_ready))
        return param_set_ulong(value, kp);
    mutex_lock(&map_ctl_lock);
    rc = skp_policy_paths_active() ? -EBUSY : param_set_ulong(value, kp);
    mutex_unlock(&map_ctl_lock);
    return rc;
}
static const struct kernel_param_ops sus_map_ino_ops = {
    .set = sus_map_ino_set,
    .get = param_get_ulong,
};
module_param_cb(map_ino, &sus_map_ino_ops, &param_map_ino, 0644);

/* dev==0 means "any filesystem": only the map_ino parameter can pick that. */
static int sus_map_add_full(unsigned long ino, dev_t dev)
{
    unsigned long flags;
    int rc = 0;

    if (!ino)
        return -EINVAL;

    spin_lock_irqsave(&map_table_lock, flags);
    if (nmap < SUS_MAP_MAX) {
        map_entries[nmap].target_ino = ino;
        map_entries[nmap].target_dev = dev;
        smp_store_release(&nmap, nmap + 1);
    } else {
        rc = -ENOSPC;
    }
    spin_unlock_irqrestore(&map_table_lock, flags);
    return rc;
}

static void sus_map_add(unsigned long ino)
{
    sus_map_add_full(ino, 0);
}

static bool sus_map_lookup(unsigned long ino, dev_t dev)
{
    int n = smp_load_acquire(&nmap);
    int i;

    for (i = 0; i < n; i++) {
        if (map_entries[i].target_ino != ino)
            continue;
        if (map_entries[i].target_dev && map_entries[i].target_dev != dev)
            continue;
        return true;
    }
    return false;
}

/* Resolve the current READER's subject and the object in one snapshot query.
 * GROUPED includes empty/exempt/no-match and must never consult the legacy table.
 * The subject-only compatibility mode deliberately retains its legacy object table;
 * UPSTREAM runs only the upstream predicate, never another snapshot-based gate. */
static bool sus_map_inode_hidden(struct inode *inode)
{
    struct skp_map_query_result result;
    enum skp_object_query_mode mode;

    mode = skp_policy_map_query(inode->i_sb->s_dev, inode->i_ino, &result);
    if (mode == SKP_OBJECT_GROUPED)
        return result.hidden != 0;
    if (mode == SKP_OBJECT_LEGACY_SUBJECT) {
        if (!result.legacy_allowed)
            return false;
    } else if (!susfs_is_current_proc_umounted_app()) {
        return false;
    }
    return sus_map_lookup(inode->i_ino, inode->i_sb->s_dev);
}

/* One handler for show_map_vma (maps) and show_smap (smaps) - both are seq_operations
 * .show callbacks that emit only what they are given, so returning 0 means "handled,
 * nothing printed" (seq_read ignores the value), which is upstream's SUS_MAP effect.
 *
 * ---- the sentinel ----
 *
 * smaps_rollup must NOT be pointed at this handler: show_smaps_rollup() is reached
 * through single_open(), whose single_start() hands .show the iterator sentinel (void *)1
 * instead of a vma, and the function ignores its v argument.  Measured with the probe
 * registered: `cat /proc/<pid>/smaps_rollup` as an app took vma->vm_file at 0xa0 -> ldr
 * from 0xa1 -> "Unable to handle kernel NULL pointer dereference at virtual address
 * 00000000000000a1", pc sus_map_skip_vma_pre+0x3c, then a panic (uptime 41346.347).
 * Unreachable from a kprobe too: upstream skips the vma *inside* the rollup loop, and
 * smap_gather_stats() is inlined by LTO here (absent from /proc/kallsyms), so only
 * walk_page_range() could be intercepted. */
static atomic_t n_show_hides = ATOMIC_INIT(0);

static int sus_map_skip_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma;
    struct inode *inode;

    vma = (struct vm_area_struct *)regs->regs[1];
    /* Defence in depth against the sentinel above: a vma is always a slab object in
     * the linear map, so anything below one page is not one - this turns a future
     * mis-registration into a lost filter, not a panic. */
    if ((unsigned long)vma < PAGE_SIZE)
        return 0;
    if (!vma->vm_file)
        return 0;
    inode = file_inode(vma->vm_file);
    if (!inode)
        return 0;
    if (sus_map_inode_hidden(inode)) {
        atomic_inc(&n_show_hides);
        /* ratelimited like sus_path's; the rule stores no path, so ino/dev name it */
        pr_info_ratelimited("sus_map: hid %s line (ino=%lu dev=%lu uid=%u)\n",
                            kp->symbol_name, inode->i_ino,
                            (unsigned long)inode->i_sb->s_dev,
                            current_uid().val);
        regs_set_return_value(regs, 0);
        regs->pc = regs->regs[30];
        return 1;
    }
    return 0;
}

static struct kprobe kp_map = {
    .symbol_name = "show_map_vma",
    .pre_handler = sus_map_skip_vma_pre,
};

static struct kprobe kp_map_smap = {
    .symbol_name = "show_smap",
    .pre_handler = sus_map_skip_vma_pre,
};

/* The outer callback survives vendor LTO that inlines show_map_vma. */
static struct kprobe kp_map_outer = {
    .symbol_name = "show_map",
    .pre_handler = sus_map_skip_vma_pre,
};

/* ---- the page-walk layer: smaps_rollup and pagemap ----
 *
 * Both listings test a vma upstream holds as a local, so neither is reachable from a
 * kprobe: no local at a function boundary, smap_gather_stats() inlined by LTO, and
 * pagemap_read() only has its vma after taking mmap_lock inside.
 *   show_smaps_rollup() -> for (vma = priv->mm->mmap; vma;) { ... skip ... }
 *   pagemap_read()      -> vma = vma_lookup(mm, start_vaddr); ... skip chunk
 * Both share one exported primitive, called with a caller-unique mm_walk_ops:
 *   smap_gather_stats(): walk_page_range(vma->vm_mm, ..., smaps_walk_ops|smaps_shmem_walk_ops, mss)
 *   pagemap_read():      walk_page_range(mm, start, end, &pagemap_ops, &pm)
 * Those three ops have no other user and every caller holds mmap_lock for read (the walk
 * asserts it), so skipping the call leaves upstream's result: the rollup vma adds nothing
 * to mss, the pagemap chunk stays unfilled and `ret = walk_page_range(...)` sees 0, as
 * upstream leaves it.  The ops are data symbols, so they come from kallsyms by name
 * (sus_mount's mnt_id_ida mechanism); if none resolves, the probe is not registered and both
 * listings stay unfiltered (logged).  The probe sits on a kernel-wide primitive, so it bails
 * out in one load and three compares - ops test first.
 *
 * Which of walk_page_range()/walk_page_vma() is the live call site cannot be assumed: with
 * CONFIG_LTO_CLANG_FULL either may be inlined into its caller (invisible to any probe - the
 * wall smap_gather_stats() hit), so both symbols are probed and walk_dbg=1 records every
 * distinct ops pointer with its call count (walk_ops), naming the real caller. */
static const void *sus_map_ops_smaps;
static const void *sus_map_ops_smaps_shmem;
static const void *sus_map_ops_pagemap;
static bool sus_map_walk_ops_done;
static atomic_t n_walk_skip = ATOMIC_INIT(0);
static atomic_t n_walk_seen = ATOMIC_INIT(0);		/* walk_page_range calls */
static atomic_t n_walk_seen_vma = ATOMIC_INIT(0);	/* walk_page_vma calls  */
/* One counter per resolution step: "the walk was not skipped" has four different causes. */
static atomic_t n_walk_ops_hit = ATOMIC_INIT(0);	/* ops was ours */
static atomic_t n_walk_scan_fail = ATOMIC_INIT(0);	/* no vma for (mm,start) */
static atomic_t n_walk_nofile = ATOMIC_INIT(0);		/* vma has no vm_file */
static atomic_t n_walk_nomatch = ATOMIC_INIT(0);	/* inode is not a rule */
static atomic_t n_walk_dbg_left = ATOMIC_INIT(4);
/* map_files symlink resolutions that were turned into ENOENT.  n_getlink_calls vs
 * n_getlink_skip keeps "the probe ran" apart from "the probe matched". */
static atomic_t n_map_files_hides = ATOMIC_INIT(0);
/* The reference map_files_get_link() took for its caller could not be handed to task_work
 * (GFP_ATOMIC or task_work_add): the call is then left as the kernel answered it - visible, but
 * not leaked - and this is the only thing that says so. */
static atomic_t n_map_files_putfail = ATOMIC_INIT(0);
static atomic_t n_getlink_calls = ATOMIC_INIT(0);
static atomic_t n_getlink_skip = ATOMIC_INIT(0);
static atomic_t n_getlink_nomatch = ATOMIC_INIT(0);

/* walk_dbg: name every ops pointer reaching the two primitives, once per value (off by default - a linear scan per call). */
static int walk_dbg;
module_param_named(walk_dbg, walk_dbg, int, 0644);

#define WALK_OPS_MAX 8
static const void *walk_seen_ops[WALK_OPS_MAX];
static atomic_t walk_seen_cnt[WALK_OPS_MAX];
static int walk_seen_n;

static void sus_map_note_ops(const void *ops)
{
    int i, n = READ_ONCE(walk_seen_n);

    for (i = 0; i < n; i++) {
        if (READ_ONCE(walk_seen_ops[i]) == ops) {
            atomic_inc(&walk_seen_cnt[i]);
            return;
        }
    }
    if (n >= WALK_OPS_MAX)
        return;
    WRITE_ONCE(walk_seen_ops[n], ops);
    atomic_inc(&walk_seen_cnt[n]);
    smp_store_release(&walk_seen_n, n + 1);
    SUSFS_LOGI("sus_map: walk ops[%d] = %pS\n", n, ops);
}

static int sus_map_walk_ops_show(char *buf, const struct kernel_param *kp)
{
    int i, n = 0, cnt = READ_ONCE(walk_seen_n);

    for (i = 0; i < cnt; i++)
        n += scnprintf(buf + n, PAGE_SIZE - n, "%2d %pS\n", i, walk_seen_ops[i]);
    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "counts: page_range=%d page_vma=%d skipped=%d\n",
                   atomic_read(&n_walk_seen), atomic_read(&n_walk_seen_vma),
                   atomic_read(&n_walk_skip));
    for (i = 0; i < cnt; i++)
        n += scnprintf(buf + n, PAGE_SIZE - n, "  [%d] n=%d\n", i,
                       atomic_read(&walk_seen_cnt[i]));
    return n;
}
static const struct kernel_param_ops sus_map_walk_ops_ops = {
    .get = sus_map_walk_ops_show,
};
module_param_cb(walk_ops, &sus_map_walk_ops_ops, NULL, 0400);

static void sus_map_resolve_walk_ops(void)
{
    if (sus_map_walk_ops_done)
        return;
    sus_map_walk_ops_done = true;

    sus_map_ops_smaps = (const void *)find_kernel_symbol_exact("smaps_walk_ops");
    sus_map_ops_smaps_shmem = (const void *)find_kernel_symbol_exact("smaps_shmem_walk_ops");
    sus_map_ops_pagemap = (const void *)find_kernel_symbol_exact("pagemap_ops");

    if (!sus_map_ops_smaps && !sus_map_ops_smaps_shmem && !sus_map_ops_pagemap) {
        pr_warn("sus_map: smaps/pagemap walk ops not found in kallsyms - "
                "smaps_rollup and pagemap stay unfiltered\n");
        return;
    }
    SUSFS_LOGI("sus_map: walk ops smaps=%px smaps_shmem=%px pagemap=%px\n",
            sus_map_ops_smaps, sus_map_ops_smaps_shmem, sus_map_ops_pagemap);
}

static bool sus_map_walk_ops_any(void)
{
    return sus_map_ops_smaps || sus_map_ops_smaps_shmem || sus_map_ops_pagemap;
}

static bool sus_map_walk_ops_ours(const void *ops)
{
    return ops && (ops == sus_map_ops_smaps || ops == sus_map_ops_smaps_shmem ||
                   ops == sus_map_ops_pagemap);
}

static bool sus_map_walk_answer(struct kprobe *kp, struct pt_regs *regs,
                                struct vm_area_struct *vma)
{
    struct inode *inode;

    /* Defence in depth, like the vma handler: a real vma is never below a page. */
    if ((unsigned long)vma < PAGE_SIZE)
        return false;
    if (!vma->vm_file) {
        atomic_inc(&n_walk_nofile);
        return false;
    }
    inode = file_inode(vma->vm_file);
    if (!inode) {
        atomic_inc(&n_walk_nofile);
        return false;
    }
    if (!sus_map_inode_hidden(inode)) {
        atomic_inc(&n_walk_nomatch);
        return false;
    }

    atomic_inc(&n_walk_skip);
    pr_info_ratelimited("sus_map: skipped %s walk for ino=%lu dev=%lu uid=%u\n",
                        kp->symbol_name, inode->i_ino,
                        (unsigned long)inode->i_sb->s_dev, current_uid().val);
    /* Both primitives return int 0 for "walked, nothing wrong" and both callers expect
     * that from a skipped walk (upstream's own skip leaves the same value).  Leaving
     * x0 = mm would turn pagemap_read()'s `ret` into a kernel pointer handed to read(2). */
    regs_set_return_value(regs, 0);
    regs->pc = regs->regs[30];
    return true;
}

/* The VMA container changed in 6.1; both spellings answer the same question - "the first
 * vma whose end is past @start", i.e. the one containing @start or the next after a gap -
 * and the caller still compares the result against vm_start.
 *   <= 6.0  mm_struct.mmap heads a doubly linked list, walked with vma->vm_next
 *   >= 6.1  that list became the mm_struct.mm_mt maple tree, walked with the vma iterator
 *           helpers VMA_ITERATOR() / for_each_vma() (mm_types.h, mm.h) - which is why
 *           "no member named 'mmap' in 'struct mm_struct'" and "'vm_next' in
 *           'struct vm_area_struct'" appeared on android14-6.1 and android15-6.6.
 * Both forms are header-only (macros and static inlines), so neither needs a kernel symbol;
 * mmap_lock is held for read by every caller, as the walk itself requires. */
static struct vm_area_struct *sus_map_find_vma(struct mm_struct *mm, unsigned long start)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	for_each_vma(vmi, vma) {
		if (start < vma->vm_end)
			return vma;
	}
	return NULL;
#else
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (start < vma->vm_end)
			break;
	}
	return vma;
#endif
}

/* walk_dbg >= 2: dump the first few resolutions past the ops test, to tell "no vma for
 * (mm, start)" from "the vma is not the expected one". */
static void sus_map_walk_dbg_log(const char *what, struct mm_struct *mm,
                                 unsigned long start, struct vm_area_struct *vma)
{
    if (walk_dbg < 2)
        return;
    if (atomic_dec_if_positive(&n_walk_dbg_left) < 0)
        return;
    SUSFS_LOGI("sus_map: %s mm=%px start=%lx mmap=%px vma=%px %lx-%lx file=%px\n",
            what, mm, start, mm ? sus_map_find_vma(mm, 0) : NULL, vma,
            vma ? vma->vm_start : 0UL, vma ? vma->vm_end : 0UL,
            (vma && vma->vm_file) ? vma->vm_file : NULL);
}

/* walk_page_range(mm, start, end, ops, private): the vma is resolved from (mm, start) as
 * the walk itself would have done, under the mmap_lock every caller of these three ops
 * holds for read - so sus_map_find_vma()'s container cannot change underneath it. */
static int sus_map_skip_walk_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const void *ops = (const void *)regs->regs[3];
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long start;

    atomic_inc(&n_walk_seen);
    if (walk_dbg)
        sus_map_note_ops(ops);
    if (!sus_map_walk_ops_ours(ops))
        return 0;

    atomic_inc(&n_walk_ops_hit);
    mm = (struct mm_struct *)regs->regs[0];
    start = (unsigned long)regs->regs[1];
    if (!mm)
        return 0;

    vma = sus_map_find_vma(mm, start);
    if (!vma || start < vma->vm_start) {
        atomic_inc(&n_walk_scan_fail);
        sus_map_walk_dbg_log("walk_page_range: no vma", mm, start, NULL);
        return 0;
    }
    sus_map_walk_dbg_log("walk_page_range: vma", mm, start, vma);

    return sus_map_walk_answer(kp, regs, vma) ? 1 : 0;
}

/* walk_page_vma(vma, ops, private): same walk, vma handed over directly. */
static int sus_map_skip_walk_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const void *ops = (const void *)regs->regs[1];

    atomic_inc(&n_walk_seen_vma);
    if (walk_dbg)
        sus_map_note_ops(ops);
    if (!sus_map_walk_ops_ours(ops))
        return 0;

    atomic_inc(&n_walk_ops_hit);
    return sus_map_walk_answer(kp, regs,
                               (struct vm_area_struct *)regs->regs[0]) ? 1 : 0;
}

static struct kprobe kp_map_walk = {
    .symbol_name = "walk_page_range",
    .pre_handler = sus_map_skip_walk_pre,
};

static struct kprobe kp_map_walk_vma = {
    .symbol_name = "walk_page_vma",
    .pre_handler = sus_map_skip_walk_vma_pre,
};

/* ---- /proc/<pid>/mem (and ptrace): the page-fetch primitive ----
 *
 * Upstream's fifth SUS_MAP site is __access_remote_vm() (mm/memory.c, patch:5667-5687):
 * after mmap_read_lock it resolves vma = vma_lookup(mm, addr) once and, inside the transfer
 * loop, breaks out when that vma's file is registered - so a read (or write) starting
 * inside a hidden mapping transfers nothing at all.  Its entry cannot be hooked usefully:
 * the lock is taken INSIDE it, and resolving a vma without that lock is a use-after-free
 * waiting for the target process to munmap.  What can be hooked is the primitive the loop
 * calls with the lock held:
 *   __access_remote_vm()       -> get_user_pages_remote(mm, addr, 1, ...)
 *   process_vm_rw_single_vec() -> pin_user_pages_remote(mm, pa, ...)
 *   (both *_remote variants require mmap_read_lock)
 * Short-circuiting that call (x0 = 0, pc = lr) makes the caller see "no page transferred":
 * __access_remote_vm returns the bytes it had already moved - 0 when the read starts inside
 * the mapping, upstream's result - and process_vm_readv takes its `pinned_pages <= 0` error
 * path.  Nothing is pinned, because the call never runs.
 *
 * The second primitive is not needed for upstream parity (upstream patches
 * __access_remote_vm only, and process_vm_readv does not go through it - measured from this
 * kernel's mm/process_vm_access.c: process_vm_rw_single_vec calls pin_user_pages_remote
 * directly); it is hooked because the same short circuit closes one more probe.
 *
 * A legacy nmap==0 is not a no-op in grouped mode. Resolve a valid file-backed
 * VMA first, then make one reader/object query. The current reader, not mm's owner,
 * selects the group. */
static atomic_t n_gup_calls = ATOMIC_INIT(0);
static atomic_t n_gup_inner_calls = ATOMIC_INIT(0);
static atomic_t n_vm_hides = ATOMIC_INIT(0);

static int sus_map_vm_access_pre(struct kprobe *kp, struct pt_regs *regs);

/* Both are thin layers of the same code and which one a call site reaches is decided by
 * LTO - measured: the __access_remote_vm path reaches get_user_pages_remote out of line (its
 * probe fired), while process_vm_readv's pin_user_pages_remote was inlined away, so that
 * wrapper's probe was removed after zero hits in every run.  __get_user_pages_remote, what
 * both wrappers end in, takes the same (mm, start) as its first two arguments and is armed
 * too; a short circuit at the outer layer stops the inner one from being reached. */
static struct kprobe kp_gup_remote = {
    .symbol_name = "get_user_pages_remote",
    .pre_handler = sus_map_vm_access_pre,
};

static struct kprobe kp_gup_remote_inner = {
    .symbol_name = "__get_user_pages_remote",
    .pre_handler = sus_map_vm_access_pre,
};

static int sus_map_vm_access_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct mm_struct *mm = (struct mm_struct *)regs->regs[0];
    unsigned long addr = regs->regs[1];
    struct vm_area_struct *vma;
    struct inode *inode;

    if (!mm || !addr)
        return 0;

    atomic_inc(kp == &kp_gup_remote_inner ? &n_gup_inner_calls : &n_gup_calls);

    /* both callers hold mmap_read_lock: the *_remote contract of this primitive */
    vma = find_vma(mm, addr);
    /* find_vma also returns the NEXT mapping after a gap. That mapping must not
     * turn an unmapped starting address into a match for a hidden file. */
    if (!vma || addr < vma->vm_start || !vma->vm_file)
        return 0;
    inode = file_inode(vma->vm_file);
    if (!inode)
        return 0;
    if (!sus_map_inode_hidden(inode))
        return 0;

    atomic_inc(&n_vm_hides);
    regs_set_return_value(regs, 0);     /* "nothing transferred" */
    regs->pc = regs->regs[30];          /* skip the call: nothing is pinned */
    return 1;
}

/* ---- /proc/<pid>/map_files/<start>-<end> ----
 *
 * Each entry is a symlink to the file mapped at that range, so `ls -l` and readlink name a
 * sus_map-registered file outright - measured: this is how the address of a mapping the maps
 * listing had already dropped was still reachable, i.e. this listing undid the hiding.
 * Upstream skips the entry in proc_map_files_readdir() (patch:1088-1095); a kprobe cannot
 * skip one entry of a readdir (the decision is a local in the middle of that function), so
 * the symlink still exists but resolving it answers ENOENT - what a checker gets for a file
 * that is not there.  The residual difference is that the range itself is still listed.
 *
 * The first attempt hooked `proc_map_files_get_link` (the i_op): it registered fine and was
 * never called.  From this kernel's fs/proc/base.c - do_readlinkat() calls i_op->readlink
 * FIRST and only falls back to vfs_readlink() (-> get_link) when it is NULL, and
 * proc_map_files uses `.readlink = proc_pid_readlink`, which ends in the per-inode callback
 * `ei->op.proc_get_link` = map_files_get_link(), the one place that hands over the MAPPED
 * file's path.  So the hook judges by inode (path->dentry), which is exact and only ever
 * fails a call that would have succeeded: the caller treats a negative return as "no link". */
/* Releasing the reference map_files_get_link() took, from task_work rather than from the probe.
 *
 * The probe's return handler runs in the exception context that fired it (arm64 raises BRK for a
 * kprobe), where sleeping is not allowed - and path_put() can sleep, because dropping the last
 * reference reaches ->d_iput().  GFP_ATOMIC and task_work_add() are both safe there; what is not
 * safe is guessing, so a failure to queue is reported and the reference is left where it was. */
struct sus_map_put_work {
	struct callback_head cb;
	struct path path;
};

static void sus_map_put_work_fn(struct callback_head *cb)
{
	struct sus_map_put_work *w = container_of(cb, struct sus_map_put_work, cb);

	path_put(&w->path);
	kfree(w);
	module_put(THIS_MODULE);
}

/* 0 when the release has been queued, -errno when it has not. */
static int sus_map_path_put_soon(const struct path *p)
{
	struct sus_map_put_work *w;

	if (!try_module_get(THIS_MODULE))
		return -ESHUTDOWN;
	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (!w) {
		module_put(THIS_MODULE);
		return -ENOMEM;
	}
	w->path = *p;
	init_task_work(&w->cb, sus_map_put_work_fn);
	if (task_work_add(current, &w->cb, TWA_RESUME)) {
		kfree(w);
		module_put(THIS_MODULE);
		return -EIO;
	}
	return 0;
}

static int sus_map_maplink_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    /* struct path *path is an output argument, filled only at return: save it here. */
    *(unsigned long *)ri->data = regs->regs[1];
    return 0;
}

static int sus_map_maplink_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long outp = *(unsigned long *)ri->data;
    const struct path *p;
    struct inode *inode;

    atomic_inc(&n_getlink_calls);
    if ((long)regs_return_value(regs) != 0 || !outp) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    p = (const struct path *)outp;
    if (!p->dentry) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    inode = d_inode(p->dentry);
    if (!inode) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    if (!sus_map_inode_hidden(inode)) {
        atomic_inc(&n_getlink_nomatch);
        return 0;
    }

    /* The reference has to change hands with the answer.  map_files_get_link() runs
     * `*path = vma->vm_file->f_path; path_get(path);` before it returns 0, and its only caller
     * releases that reference on the SUCCESS path alone (proc_pid_readlink():
     * `if (error) goto out; ... path_put(&path);`).  Turning the return into -ENOENT without
     * taking the reference over leaked a dentry and a mount reference on every resolution of a
     * hidden mapping's symlink - the mapped file keeps its own reference, so the dentry is never
     * reclaimed and the mount can never be unmounted, and an app uid can do it in a loop.
     *
     * It cannot be released here (see sus_map_path_put_soon()), so it goes to task_work.  If even
     * that fails the call keeps the kernel's own answer: a symlink that resolves is a tell, a
     * silent leak is not. */
    if (sus_map_path_put_soon(p)) {
        atomic_inc(&n_map_files_putfail);
        return 0;
    }
    atomic_inc(&n_map_files_hides);
    pr_info_ratelimited("sus_map: hid map_files symlink to ino=%lu (uid=%u)\n",
                        inode->i_ino, current_uid().val);
    regs_set_return_value(regs, (unsigned long)(long)-ENOENT);
    return 0;
}

static struct kretprobe kr_map_files = {
    .kp.symbol_name = "map_files_get_link",
    .entry_handler = sus_map_maplink_entry,
    .handler = sus_map_maplink_ret,
    .data_size = sizeof(unsigned long),	/* the output struct path * */
    .maxactive = 16,
};
static bool kr_map_files_ok;

/* Kept in one table so init and exit cannot drift apart. */
static struct kprobe *const map_probes[] = {
    &kp_map, &kp_map_smap, &kp_map_walk, &kp_map_walk_vma,
    &kp_gup_remote, &kp_gup_remote_inner, &kp_map_outer,
};
#define N_MAP_PROBES ARRAY_SIZE(map_probes)
static bool map_registered;
static bool map_probe_armed[N_MAP_PROBES];

/* Reachability, not configuration: "the probe is registered" says nothing on a kernel built
 * with CONFIG_LTO_CLANG_FULL, where the call site it should catch may have been inlined away
 * (walk_page_range() is EXPORT_SYMBOL_GPL and LTO may still inline the calls inside
 * pagemap_read()/smap_gather_stats()).  walk_seen == 0 while a rule matches fingerprints such
 * an inlined call site, not a rule that failed to match. */
static int sus_map_stat_show(char *buf, const struct kernel_param *kp)
{
    int i, armed = 0;

    for (i = 0; i < (int)N_MAP_PROBES; i++)
        armed += map_probe_armed[i] ? 1 : 0;

    return scnprintf(buf, PAGE_SIZE,
                     "legacy_rules=%d grouped=%d routes=0x%x armed=%d/%d walk_seen=%d walk_vma=%d walk_skipped=%d "
                     "ops_hit=%d scan_fail=%d nofile=%d nomatch=%d getlink: calls=%d skip=%d nomatch=%d hides=%d putfail=%d line_hides=%d\n"
                     "vm: gup_calls=%d inner_calls=%d hides=%d\n"
                     "ops: smaps=%px smaps_shmem=%px pagemap=%px\n",
                     READ_ONCE(nmap), skp_policy_paths_active(),
                     susfs_map_group_routes(), armed, (int)N_MAP_PROBES,
                     atomic_read(&n_walk_seen), atomic_read(&n_walk_seen_vma),
                     atomic_read(&n_walk_skip),
                     atomic_read(&n_walk_ops_hit), atomic_read(&n_walk_scan_fail),
                     atomic_read(&n_walk_nofile), atomic_read(&n_walk_nomatch),
                     atomic_read(&n_getlink_calls), atomic_read(&n_getlink_skip),
                     atomic_read(&n_getlink_nomatch), atomic_read(&n_map_files_hides),
                     atomic_read(&n_map_files_putfail), atomic_read(&n_show_hides),
                     atomic_read(&n_gup_calls), atomic_read(&n_gup_inner_calls),
                     atomic_read(&n_vm_hides),
                     sus_map_ops_smaps, sus_map_ops_smaps_shmem,
                     sus_map_ops_pagemap);
}
static const struct kernel_param_ops sus_map_stat_ops = {
    .get = sus_map_stat_show,
};
module_param_cb(map_stat, &sus_map_stat_ops, NULL, 0400);

/* Serialises probe arming.  register_kprobe() answers -EINVAL once another task has resolved
 * .addr, and the failure branch below clears .addr - without this lock that disarms a probe that
 * is LIVE: its breakpoint stays installed and unregister_kprobe() can no longer take it out, so
 * it would survive the unload with a handler pointing into freed module text.  Two tasks can add
 * a rule at the same time (every supercall runs in its own task_work), and susfs_sus_map_init()
 * reaches this too. */
/* Registers whichever of the probes are not up yet.  Called from init (when a rule
 * already exists) and from the supercall that adds the first rule, so both paths arm
 * exactly the same set. */
static int sus_map_register_probes_locked(void)
{
    int i, n = 0, first_err = 0;
    int ret;

    lockdep_assert_held(&map_ctl_lock);
    sus_map_resolve_walk_ops();

    for (i = 0; i < (int)N_MAP_PROBES; i++) {
        int rc;

        if (map_probe_armed[i])
            continue;
        if ((map_probes[i] == &kp_map_walk || map_probes[i] == &kp_map_walk_vma) &&
            !sus_map_walk_ops_any())
            continue;
        rc = register_kprobe(map_probes[i]);
        if (rc) {
            pr_warn("sus_map: register_kprobe(%s) failed %d - that listing is not filtered\n",
                    map_probes[i]->symbol_name, rc);
            /* This function is retried from the supercall that adds a rule (and it skips the
             * probes that did arm), so the struct has to be clear for the retry to reach the
             * symbol again: a failure after address resolution leaves .addr set - see
             * susfs_kprobe.h. */
            susfs_kp_forget_addr(map_probes[i]);
            if (!first_err)
                first_err = rc;
            continue;
        }
        map_probe_armed[i] = true;
        n++;
    }

    if (n)
        SUSFS_LOGI("sus_map: %d/%d probes armed (%d rules)\n",
                n, (int)N_MAP_PROBES, nmap);

    /* The map_files hook is a kretprobe, so it lives outside map_probes[] (which
     * holds struct kprobe *) and is tracked on its own; optional like the rest. */
    if (!kr_map_files_ok) {
        int rc = register_kretprobe(&kr_map_files);

        if (rc) {
            susfs_krp_forget_addr(&kr_map_files);
            pr_warn("sus_map: register_kretprobe(proc_map_files_get_link) failed %d - readlink on a hidden mapping still names the file\n",
                    rc);
        } else {
            kr_map_files_ok = true;
        }
    }

    map_registered = map_probe_armed[0] || map_probe_armed[6];
    ret = map_registered ? 0 : first_err;

    return ret;
}

static int sus_map_register_probes(void)
{
    int rc;

    mutex_lock(&map_ctl_lock);
    rc = sus_map_register_probes_locked();
    mutex_unlock(&map_ctl_lock);
    return rc;
}

void susfs_map_group_write_begin(void)
{
    mutex_lock(&map_ctl_lock);
}

void susfs_map_group_write_end(void)
{
    mutex_unlock(&map_ctl_lock);
}

int susfs_map_group_prepare_locked(void)
{
    lockdep_assert_held(&map_ctl_lock);
    /* Every route is optional as upstream. Publication is allowed with an
     * incomplete mask; status must report the actual routes, not "all ready". */
    (void)sus_map_register_probes_locked();
    return 0;
}

u32 susfs_map_group_routes(void)
{
    u32 routes = 0;
    int i;

    /* Preserve the existing route bits: 0..5 are the original probes,
     * 6 = map_files_get_link, 7..9 = resolved walk ops, 10 = show_map.
     * Armed does not establish reachability through an LTO-inlined caller. */
    for (i = 0; i < (int)N_MAP_PROBES; i++)
        if (READ_ONCE(map_probe_armed[i]))
            routes |= 1U << (i == 6 ? 10 : i);
    if (READ_ONCE(kr_map_files_ok))
        routes |= 1U << 6;
    if (READ_ONCE(sus_map_ops_smaps))
        routes |= 1U << 7;
    if (READ_ONCE(sus_map_ops_smaps_shmem))
        routes |= 1U << 8;
    if (READ_ONCE(sus_map_ops_pagemap))
        routes |= 1U << 9;
    return routes;
}

int susfs_sus_map_init(void)
{
    int rc;

    WRITE_ONCE(map_ready, true);
    sus_map_add(param_map_ino);
    if (nmap == 0) {
        SUSFS_LOGI("sus_map: no rules, hook not installed\n");
        return 0;
    }

    /* Every probe is optional on its own: without show_smap the maps listing is still
     * filtered, so one missing symbol must not take the rest down. */
    rc = sus_map_register_probes();
    if (rc)
        return rc;
    return 0;
}

void susfs_sus_map_exit(void)
{
    int i;

    /* Same lock as the registration side.  The arm path is check-then-act on map_probe_armed[],
     * so disarming without it would break the invariant the duplicate-registration fix
     * established: one probe's arm and disarm belong under the same lock.  (No /proc write
     * reaches the arm path today - it runs from init and the supercall, and the supercall's
     * task_work holds a module reference - so this is symmetry rather than a live window.) */
    mutex_lock(&map_ctl_lock);
    for (i = 0; i < (int)N_MAP_PROBES; i++) {
        if (!map_probe_armed[i])
            continue;
        unregister_kprobe(map_probes[i]);
        susfs_kp_forget_addr(map_probes[i]);
        map_probe_armed[i] = false;
    }
    if (kr_map_files_ok) {
        unregister_kretprobe(&kr_map_files);
        susfs_krp_forget_addr(&kr_map_files);
        kr_map_files_ok = false;
    }
    map_registered = false;
    WRITE_ONCE(map_ready, false);
    mutex_unlock(&map_ctl_lock);

    /* Published the way sus_map_add_full() does it (smp_store_release against the
     * smp_load_acquire readers); a plain store would break that protocol.  No reader can be live
     * by now - every probe is unregistered above - but the write should still have the right
     * shape. */
    smp_store_release(&nmap, 0);
}

/* supercall: CMD_SUSFS_ADD_SUS_MAP (resolve path -> ino/dev, register hook) */
void susfs_sus_map_supercall(void __user **arg)
{
    struct st_susfs_sus_map info = {0};
    struct path p;
    struct inode *inode;
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    /* char[256] field that need not be NUL-terminated: reject it before kern_path() can read off the end of our stack copy. */
    if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {
        info.err = -ENAMETOOLONG;
        goto out;
    }

    rc = kern_path(info.target_pathname, LOOKUP_FOLLOW, &p);
    if (rc) {
        info.err = rc;
        goto out;
    }
    inode = d_backing_inode(p.dentry);
    if (!inode) {
        path_put(&p);
        info.err = -ENOENT;
        goto out;
    }

    mutex_lock(&map_ctl_lock);
    if (skp_policy_paths_active()) {
        info.err = -EBUSY;
        goto unlock;
    }
    /* One call fills both fields; table publication and group publication share
     * this mutex. A candidate resolving before group takeover is rechecked here. */
    rc = sus_map_add_full(inode->i_ino, inode->i_sb->s_dev);
    if (rc) {
        info.err = rc;
        goto unlock;
    }
    SUSFS_LOGI("sus_map: added %s (ino=%lu) via supercall\n",
            info.target_pathname, inode->i_ino);
    if (!map_registered) {
        rc = sus_map_register_probes_locked();
        if (rc) {
            info.err = rc;
            goto unlock;
        }
    }
    info.err = 0;
unlock:
    mutex_unlock(&map_ctl_lock);
    /* path_put can sleep/reenter VFS; never release under writer locks. */
    path_put(&p);
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_map __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_map supercall copy_to_user failed\n");
}
