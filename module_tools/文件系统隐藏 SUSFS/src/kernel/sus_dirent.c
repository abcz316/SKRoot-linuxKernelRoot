// SPDX-License-Identifier: GPL-2.0
/* Compose SUSFS with the actor selected by the original directory syscall.
 * No private getdents layout, direct iterate_dir replay or user-buffer writes.
 * Initial coverage is native getdents64 on qualified ext4/F2FS only. */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <asm/ptrace.h>
#include "susfs.h"
#include "skp_policy_adapter.h"
#include "susfs_dirent.h"
#include "susfs_dir_name.h"
#include "susfs_log.h"
#include "symbol_resolver.h"
#include "btf_layout.h"
#include "susfs_kprobe.h"

/* DDK-qualified layouts; live text, BTF and callback CFI still have to agree. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
#define SD_CALL_OFFSET 0x8c
#define SD_POST_OFFSET 0x90
#define SD_BODY_OFFSET 0x5c
#define SD_STACK_BYTES 64
#define SD_CONTEXT_REG 22
#define SD_ACTOR_CFI 0xb1edbef0U
#define SD_ITERATE_CFI 0x53f92671U
#define SD_FILE_POS 80
#define SD_FILE_OP 192
#define SD_ITERATE_OP 56
#else
#define SD_CALL_OFFSET 0x7c
#define SD_POST_OFFSET 0x80
#define SD_BODY_OFFSET 0x4c
#define SD_STACK_BYTES 48
#define SD_CONTEXT_REG 20
#define SD_ACTOR_CFI 0x4737d63bU
#define SD_ITERATE_CFI 0x1e66475cU
#define SD_FILE_POS 128
#define SD_FILE_OP 16
#define SD_ITERATE_OP 64
#endif
#define SD_MAXACTIVE 256
#define SD_MAX_BUCKET_CALLS 64

struct susfs_dirent_guard {
	struct susfs_dirent_call *call;
	struct susfs_dirent_guard *parent;
	struct file *file;
	struct dir_context *ctx;
	unsigned long entry_sp;
	bool eligible;
	bool at_call;
};

static struct file *(*sd_fget)(unsigned int);
static bool prefilter;
module_param(prefilter, bool, 0444);
MODULE_PARM_DESC(prefilter, "Compatibility parameter; direct directory prefilter is disabled");
static DEFINE_HASHTABLE(sd_calls, 8);
static DEFINE_RAW_SPINLOCK(sd_lock);
static DEFINE_MUTEX(sd_stop_lock);
static DECLARE_WAIT_QUEUE_HEAD(sd_wait);
static bool sd_ready, sd_accepting, sd_call_installed, sd_post_installed, sd_return_installed;
static int sd_qualification_error;
static atomic_t sd_active = ATOMIC_INIT(0);
static atomic_t sd_bindings = ATOMIC_INIT(0);
static atomic64_t sd_begun = ATOMIC64_INIT(0);
static atomic64_t sd_covered = ATOMIC64_INIT(0);
static atomic64_t sd_fallback = ATOMIC64_INIT(0);
static atomic64_t sd_attached = ATOMIC64_INIT(0);
static atomic64_t sd_restored = ATOMIC64_INIT(0);
static atomic64_t sd_ret_recovered = ATOMIC64_INIT(0);
static atomic64_t sd_forwarded = ATOMIC64_INIT(0);
static atomic64_t sd_hidden = ATOMIC64_INIT(0);
static atomic64_t sd_conflicts = ATOMIC64_INIT(0);
static atomic64_t sd_entry_misses = ATOMIC64_INIT(0);
static atomic64_t sd_reject_compat = ATOMIC64_INIT(0);
static atomic64_t sd_reject_not_ready = ATOMIC64_INIT(0);
static atomic64_t sd_reject_file = ATOMIC64_INIT(0);
static atomic64_t sd_reject_filesystem = ATOMIC64_INIT(0);
static unsigned long sd_iterate_address;
static const struct file_operations *sd_ext4_dir_ops, *sd_f2fs_dir_ops;
static struct kretprobe sd_return_probe;
static struct kprobe sd_call_probe, sd_post_probe;

static bool sd_actor(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int type);
static_assert(__builtin_types_compatible_p(filldir_t, typeof(&sd_actor)),
	      "directory actor must retain the kernel filldir_t CFI type");

__nocfi struct file *susfs_dirent_file_get(unsigned int fd)
{
	struct file *(*get_file)(unsigned int) = READ_ONCE(sd_fget);
	return get_file ? get_file(fd) : NULL;
}

/* fget remains usable when actor qualification failed and the saved syscall
 * needs the existing post-filter fallback. */
bool susfs_dirent_file_lookup_ready(void)
{
	return READ_ONCE(sd_fget) != NULL;
}

/* Old ABI compatibility. It must never recreate the direct-iteration bypass. */
__nocfi bool susfs_dirent_prefilter(const struct pt_regs *regs, long *out, bool compat)
{
	return false;
}

static struct susfs_dirent_call *sd_current_locked(void)
{
	struct susfs_dirent_call *call;
	hash_for_each_possible(sd_calls, call, node, (unsigned long)current)
		if (call->task == current)
			return call;
	return NULL;
}

static struct susfs_dirent_call *sd_bound_locked(struct dir_context *ctx)
{
	struct susfs_dirent_call *call;
	hash_for_each_possible(sd_calls, call, node, (unsigned long)current)
		if (call->task == current && call->bound && call->bound_ctx == ctx)
			return call;
	return NULL;
}

static bool sd_local_file(struct file *file)
{
	struct inode *inode;
	unsigned long magic;
	if (!file || !(inode = file_inode(file)) || !inode->i_sb)
		return false;
	magic = inode->i_sb->s_magic;
	return (magic == EXT4_SUPER_MAGIC && sd_ext4_dir_ops && READ_ONCE(file->f_op) == sd_ext4_dir_ops) ||
	       (magic == F2FS_SUPER_MAGIC && sd_f2fs_dir_ops && READ_ONCE(file->f_op) == sd_f2fs_dir_ops);
}

bool susfs_dirent_composed_ready(void)
{
	return READ_ONCE(sd_ready) && READ_ONCE(sd_accepting);
}

bool susfs_dirent_begin(struct susfs_dirent_call *call, struct file *file, bool compat)
{
	struct hlist_node *node;
	unsigned long flags;
	unsigned int count = 0;
	if (!call)
		return false;
	memset(call, 0, sizeof(*call));
	if (compat) {
		atomic64_inc(&sd_reject_compat);
		return false;
	}
	if (!susfs_dirent_composed_ready()) {
		atomic64_inc(&sd_reject_not_ready);
		return false;
	}
	if (!file) {
		atomic64_inc(&sd_reject_file);
		return false;
	}
	if (!sd_local_file(file)) {
		atomic64_inc(&sd_reject_filesystem);
		return false;
	}
	/* Acquire before waiting on a lock or entering the possibly sleeping orig. */
	if (!try_module_get(THIS_MODULE))
		return false;
	raw_spin_lock_irqsave(&sd_lock, flags);
	if (!sd_accepting) {
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		module_put(THIS_MODULE);
		return false;
	}
	/* Recursive saved syscall chains share the outer task's iterator state.
	 * Keep a single owner request so an inner same-ctx iteration can pause its
	 * outer binding instead of looking past it through a second request. */
	{
		struct susfs_dirent_call *outer = sd_current_locked();
		if (outer) {
			outer->failed = true;
			raw_spin_unlock_irqrestore(&sd_lock, flags);
			module_put(THIS_MODULE);
			return false;
		}
	}
	/* Bound lock-held traversal without a global fixed state pool. Saturated
	 * hash buckets decline this call before any actor can be modified. */
	hlist_for_each(node, &sd_calls[hash_min((unsigned long)current, HASH_BITS(sd_calls))]) {
		if (++count < SD_MAX_BUCKET_CALLS)
			continue;
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		module_put(THIS_MODULE);
		return false;
	}
	call->task = current;
	call->file = file;
	call->active = true;
	call->call_missed = READ_ONCE(sd_call_probe.nmissed);
	call->post_missed = READ_ONCE(sd_post_probe.nmissed);
	call->return_missed = READ_ONCE(sd_return_probe.nmissed);
	hash_add(sd_calls, &call->node, (unsigned long)current);
	atomic_inc(&sd_active);
	atomic64_inc(&sd_begun);
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return true;
}

static void sd_set_actor(struct dir_context *ctx, filldir_t actor)
{
	filldir_t *slot = (filldir_t *)((char *)ctx + offsetof(struct dir_context, actor));
	WRITE_ONCE(*slot, actor);
}

/* Called only while the real iterator still owns its context. */
static bool sd_restore_locked(struct susfs_dirent_call *call)
{
	bool clean = true;
	if (!call->bound)
		return false;
	if (call->callbacks || READ_ONCE(call->bound_ctx->actor) != sd_actor) {
		call->failed = true;
		atomic64_inc(&sd_conflicts);
		clean = false;
	} else {
		sd_set_actor(call->bound_ctx, call->original_actor);
		call->restored++;
		atomic64_inc(&sd_restored);
	}
	call->bound = false;
	call->bound_ctx = NULL;
	call->original_actor = NULL;
	atomic_dec(&sd_bindings);
	return clean;
}

/* A recursive iterator can reuse the outer context while an original actor
 * is on the stack. Stop composing it before that inner iterator starts; the
 * current actor invocation already holds its copied original pointer. */
static void sd_pause_nested_locked(struct susfs_dirent_call *call, struct dir_context *ctx)
{
	if (!call->bound || call->bound_ctx != ctx)
		return;
	if (READ_ONCE(ctx->actor) == sd_actor) {
		sd_set_actor(ctx, call->original_actor);
		call->restored++;
		atomic64_inc(&sd_restored);
	} else {
		atomic64_inc(&sd_conflicts);
	}
	call->bound = false;
	call->bound_ctx = NULL;
	call->original_actor = NULL;
	call->failed = true;
	atomic_dec(&sd_bindings);
}

bool susfs_dirent_end(struct susfs_dirent_call *call)
{
	unsigned long flags;
	bool covered;
	if (!call || !call->active) {
		atomic64_inc(&sd_fallback);
		return false;
	}
	raw_spin_lock_irqsave(&sd_lock, flags);
	/* orig has returned: its getdents stack is retired. Do not read ctx here.
	 * These admitted filesystems invoke the actor synchronously, so no legal
	 * future actor call remains. A lost restore is reported as weak coverage. */
	if (call->bound) {
		call->bound = false;
		call->bound_ctx = NULL;
		call->original_actor = NULL;
		call->failed = true;
		atomic_dec(&sd_bindings);
		atomic64_inc(&sd_conflicts);
	}
	if (call->guard || call->callbacks) {
		call->failed = true;
		atomic64_inc(&sd_conflicts);
	}
	/* A skipped nested entry/callsite must not make an incomplete original
	 * chain look like one fully observed iterator. Global increments from a
	 * different task may conservatively select fallback, which is safe. */
	if (call->call_missed != READ_ONCE(sd_call_probe.nmissed) ||
	    call->post_missed != READ_ONCE(sd_post_probe.nmissed) ||
	    call->return_missed != READ_ONCE(sd_return_probe.nmissed))
		call->failed = true;
	covered = !call->failed && call->iterations == 1 && call->attached == 1 && call->restored == 1;
	hash_del(&call->node);
	call->active = false;
	call->guard = NULL;
	atomic_dec(&sd_active);
	atomic64_inc(covered ? &sd_covered : &sd_fallback);
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	wake_up_all(&sd_wait);
	module_put(THIS_MODULE);
	return covered;
}

/* A typed call preserves the original actor's KCFI check. This function must
 * not be __nocfi: both callback prototypes are the exact audited 6.12 ABI. */
static noinline bool sd_call_actor(filldir_t original, struct dir_context *ctx,
		const char *name, int namlen, loff_t offset, u64 ino, unsigned int type)
{
	return original(ctx, name, namlen, offset, ino, type);
}

static bool sd_actor(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int type)
{
	struct susfs_dirent_call *call;
	const struct super_block *sb;
	const struct dentry *directory;
	filldir_t original;
	unsigned long flags;
	bool answer;
	raw_spin_lock_irqsave(&sd_lock, flags);
	call = sd_bound_locked(ctx);
	if (!call || !call->original_actor || call->original_actor == sd_actor) {
		atomic64_inc(&sd_conflicts);
		WRITE_ONCE(sd_accepting, false);
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return false;
	}
	call->callbacks++;
	original = call->original_actor;
	sb = file_inode(call->file)->i_sb;
	directory = call->file->f_path.dentry;
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	/* No lock or RCU read-side section may span the original actor. */
	if ((name && namlen > 0 && namlen <= NAME_MAX &&
             !(namlen == 1 && name[0] == '.') &&
             !(namlen == 2 && name[0] == '.' && name[1] == '.') &&
             skp_policy_path_contents_hidden(directory, true)) ||
            sus_path_dirent_hidden_n(sb, ino, name, namlen) ||
	    susfs_directory_entry_hidden(name, namlen, type)) {
		atomic64_inc(&sd_hidden);
		answer = true;
	} else {
		atomic64_inc(&sd_forwarded);
		answer = sd_call_actor(original, ctx, name, namlen, offset, ino, type);
	}
	raw_spin_lock_irqsave(&sd_lock, flags);
	call->callbacks--;
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return answer;
}

static int sd_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct susfs_dirent_guard *guard = (void *)ri->data;
	struct susfs_dirent_call *call;
	unsigned long flags;
	memset(guard, 0, sizeof(*guard));
	raw_spin_lock_irqsave(&sd_lock, flags);
	call = sd_current_locked();
	if (!call) {
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return 1;
	}
	call->iterations++;
	guard->call = call;
	guard->parent = call->guard;
	guard->file = (void *)regs->regs[0];
	guard->ctx = (void *)regs->regs[1];
	guard->entry_sp = regs->sp;
	guard->eligible = !guard->parent && call->iterations == 1 && guard->ctx && guard->file == call->file;
	if (!guard->eligible) {
		call->failed = true;
		sd_pause_nested_locked(call, guard->ctx);
	}
	call->guard = guard;
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return 0;
}

static bool sd_actor_qualified(filldir_t actor)
{
	u32 cfi;
	return actor && actor != sd_actor &&
	       !copy_from_kernel_nofault(&cfi, (const void *)((unsigned long)actor - 4), 4) && cfi == SD_ACTOR_CFI;
}

static int sd_at_call(struct kprobe *kp, struct pt_regs *regs)
{
	struct susfs_dirent_call *call;
	struct susfs_dirent_guard *guard;
	filldir_t actual;
	unsigned long flags;
	raw_spin_lock_irqsave(&sd_lock, flags);
	call = sd_current_locked();
	if (!call) {
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return 0;
	}
	guard = call->guard;
	if (!guard || guard->file != (void *)regs->regs[0] || guard->ctx != (void *)regs->regs[1] ||
	    regs->sp + SD_STACK_BYTES != guard->entry_sp) {
		call->failed = true;
		sd_pause_nested_locked(call, (void *)regs->regs[1]);
		atomic64_inc(&sd_entry_misses);
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return 0;
	}
	guard->at_call = true;
	if (!guard->eligible || call->bound || !READ_ONCE(sd_accepting) || !sd_local_file(call->file)) {
		call->failed = true;
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return 0;
	}
	actual = READ_ONCE(guard->ctx->actor);
	if (!sd_actor_qualified(actual)) {
		call->failed = true;
		atomic64_inc(&sd_conflicts);
		raw_spin_unlock_irqrestore(&sd_lock, flags);
		return 0;
	}
	call->bound_ctx = guard->ctx;
	call->original_actor = actual;
	call->bound_sp = regs->sp;
	call->bound = true;
	call->attached++;
	atomic_inc(&sd_bindings);
	atomic64_inc(&sd_attached);
	sd_set_actor(guard->ctx, sd_actor);
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return 0;
}

static int sd_after_call(struct kprobe *kp, struct pt_regs *regs)
{
	struct susfs_dirent_call *call;
	struct susfs_dirent_guard *guard;
	unsigned long flags;
	raw_spin_lock_irqsave(&sd_lock, flags);
	call = sd_current_locked();
	if (call) {
		guard = call->guard;
		if (guard && guard->file == (void *)regs->regs[19] && guard->ctx == (void *)regs->regs[SD_CONTEXT_REG] &&
		    regs->sp + SD_STACK_BYTES == guard->entry_sp && call->bound &&
		    call->bound_ctx == guard->ctx && call->bound_sp == regs->sp)
			sd_restore_locked(call);
	}
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return 0;
}

static int sd_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct susfs_dirent_guard *guard = (void *)ri->data;
	struct susfs_dirent_call *call = guard->call;
	unsigned long flags;
	if (!call)
		return 0;
	raw_spin_lock_irqsave(&sd_lock, flags);
	if (call->guard != guard) {
		call->failed = true;
		atomic64_inc(&sd_conflicts);
	} else {
		if (call->bound && call->bound_ctx == guard->ctx && guard->at_call && guard->eligible) {
			if (sd_restore_locked(call))
				atomic64_inc(&sd_ret_recovered);
		}
		call->guard = guard->parent;
	}
	guard->call = NULL;
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	return 0;
}

static struct kretprobe sd_return_probe = {
	.kp.symbol_name = "iterate_dir", .entry_handler = sd_enter,
	.handler = sd_return, .data_size = sizeof(struct susfs_dirent_guard), .maxactive = SD_MAXACTIVE,
};
static struct kprobe sd_call_probe = { .pre_handler = sd_at_call };
static struct kprobe sd_post_probe = { .pre_handler = sd_after_call };

static int sd_check_field(const char *structure, const char *field, const char *type, size_t expected)
{
	size_t actual;
	int rc = susfs_btf_field_offset(structure, field, type, &actual);
	return rc ? rc : actual == expected ? 0 : -EPROTO;
}

static int sd_qualify(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
	static const u32 body[] = {
		0xf9402a68U,0xaa1303e0U,0xaa1603e1U,0xf90006c8U,0xf9406268U,
		0xf9401d08U,0xb85fc110U,0x7284ce31U,0x72aa7f31U,0x6b11021fU,
		0x54000040U,0xd4304500U,0xd63f0100U,0xb9401668U,0x5288000aU,
		0xf94006c9U,0x72a0800aU,0x2a0003f5U,0x6a0a011fU,0xf9002a69U
	};
	static const u32 prologue[] = {0xd503233fU,0xa9bc7bfdU,0xf9000bf7U,0xa90257f6U,0xa9034ff4U,0x910003fdU};
#else
	static const u32 body[] = {
		0xf9404268U,0xaa1303e0U,0xaa1403e1U,0xf9000688U,0xf9400a68U,
		0xf9402108U,0xb85fc110U,0x7288eb91U,0x72a3ccd1U,0x6b11021fU,
		0x54000040U,0xd4304500U,0xd63f0100U,0xb9400e68U,0x5288000aU,
		0xf9400689U,0x72a0800aU,0x2a0003f4U,0x6a0a011fU,0xf9004269U
	};
	static const u32 prologue[] = {0xd503233fU,0xa9bd7bfdU,0xf9000bf5U,0xa9024ff4U,0x910003fdU};
#endif
	static const char *const iterate_params[] = {"file*", "dir_context*"};
	size_t size;
	u32 words[ARRAY_SIZE(body)], prefix;
	unsigned int i;
	int rc;
#if !((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)) || \
      (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0))) || \
    !defined(CONFIG_ARM64) || !defined(CONFIG_CFI_CLANG)
	return -EOPNOTSUPP;
#endif
	sd_iterate_address = find_kernel_symbol_exact("iterate_dir");
	if (!sd_iterate_address)
		return -ENOENT;
	if (copy_from_kernel_nofault(words, (void *)(sd_iterate_address + SD_BODY_OFFSET), sizeof(body)) || memcmp(words, body, sizeof(body)))
		return -ESTALE;
	if (copy_from_kernel_nofault(words, (void *)sd_iterate_address, sizeof(prologue)) || memcmp(words, prologue, sizeof(prologue)))
		return -ESTALE;
	if (copy_from_kernel_nofault(&prefix, (void *)(sd_iterate_address - 4), 4) || prefix != SD_ITERATE_CFI ||
	    copy_from_kernel_nofault(&prefix, (void *)((unsigned long)sd_actor - 4), 4) || prefix != SD_ACTOR_CFI)
		return -EPROTO;
	rc = susfs_btf_layout_init();
	if (rc)
		return rc;
	rc = susfs_btf_struct_size("dir_context", &size);
	if (rc || size != sizeof(struct dir_context))
		return rc ? rc : -EPROTO;
#define SD_FIELD(st, field, type) do { rc = sd_check_field(#st, #field, type, offsetof(struct st, field)); if (rc) return rc; } while (0)
	SD_FIELD(dir_context, actor, "filldir_t");
	SD_FIELD(dir_context, pos, "loff_t");
	SD_FIELD(file, f_inode, "inode*");
	SD_FIELD(file, f_op, "file_operations*");
	SD_FIELD(file, f_pos, "loff_t");
	SD_FIELD(inode, i_sb, "super_block*");
	SD_FIELD(super_block, s_magic, "ulong");
#undef SD_FIELD
	rc = susfs_btf_callback_offset("file_operations", "iterate_shared", "int",
		iterate_params, ARRAY_SIZE(iterate_params), &size);
	if (rc || size != offsetof(struct file_operations, iterate_shared))
		return rc ? rc : -EPROTO;
	rc = susfs_btf_check_function("iterate_dir", "int", iterate_params, ARRAY_SIZE(iterate_params));
	if (rc)
		return rc;
	/* The qualified instructions embed these target-specific field offsets.
	 * Refuse layout changes even if the C compiler's header would accept them. */
	if (offsetof(struct file, f_pos) != SD_FILE_POS || offsetof(struct file, f_op) != SD_FILE_OP ||
	    offsetof(struct file_operations, iterate_shared) != SD_ITERATE_OP)
		return -EPROTO;
	for (i = 0; i < ARRAY_SIZE(body); i++)
		if (!body[i])
			return -EPROTO;
	return 0;
}

int susfs_dirent_status_json(char *buffer, size_t capacity)
{
	return scnprintf(buffer, capacity,
		"{\"native\":%s,\"compat\":false,\"filesystems\":[%s%s],\"active\":%d,\"bindings\":%d,\"begun\":%lld,\"covered\":%lld,\"fallback\":%lld,\"attached\":%lld,\"restored\":%lld,\"ret_recovered\":%lld,\"forwarded\":%lld,\"hidden\":%lld,\"conflicts\":%lld,\"entry_misses\":%lld,\"nmissed\":%d,\"call_nmissed\":%lu,\"post_nmissed\":%lu,\"qualification_error\":%d,\"reject_compat\":%lld,\"reject_not_ready\":%lld,\"reject_file\":%lld,\"reject_filesystem\":%lld}",
		susfs_dirent_composed_ready() ? "true" : "false",
		sd_ext4_dir_ops ? "\"ext4\"" : "",
		sd_f2fs_dir_ops ? (sd_ext4_dir_ops ? ",\"f2fs\"" : "\"f2fs\"") : "",
		atomic_read(&sd_active), atomic_read(&sd_bindings),
		atomic64_read(&sd_begun), atomic64_read(&sd_covered), atomic64_read(&sd_fallback),
		atomic64_read(&sd_attached), atomic64_read(&sd_restored), atomic64_read(&sd_ret_recovered),
		atomic64_read(&sd_forwarded), atomic64_read(&sd_hidden), atomic64_read(&sd_conflicts),
		atomic64_read(&sd_entry_misses), READ_ONCE(sd_return_probe.nmissed),
		READ_ONCE(sd_call_probe.nmissed), READ_ONCE(sd_post_probe.nmissed), READ_ONCE(sd_qualification_error),
		atomic64_read(&sd_reject_compat), atomic64_read(&sd_reject_not_ready),
		atomic64_read(&sd_reject_file), atomic64_read(&sd_reject_filesystem));
}
int susfs_dirent_stat_line(char *buffer, size_t capacity)
{
	return scnprintf(buffer, capacity, "dirent_composed=%u active=%d bindings=%d fallback=%lld conflicts=%lld nmissed=%d\n",
		susfs_dirent_composed_ready(), atomic_read(&sd_active), atomic_read(&sd_bindings),
		atomic64_read(&sd_fallback), atomic64_read(&sd_conflicts), READ_ONCE(sd_return_probe.nmissed));
}

void susfs_dirent_stop(void)
{
	unsigned long flags;
	mutex_lock(&sd_stop_lock);
	raw_spin_lock_irqsave(&sd_lock, flags);
	WRITE_ONCE(sd_accepting, false);
	raw_spin_unlock_irqrestore(&sd_lock, flags);
	if (sd_call_installed) {
		unregister_kprobe(&sd_call_probe);
		sd_call_installed = false;
	}
	wait_event(sd_wait, !atomic_read(&sd_active));
	if (sd_post_installed) {
		unregister_kprobe(&sd_post_probe);
		sd_post_installed = false;
	}
	if (sd_return_installed) {
		unregister_kretprobe(&sd_return_probe);
		sd_return_installed = false;
	}
	WRITE_ONCE(sd_ready, false);
	mutex_unlock(&sd_stop_lock);
}

int susfs_sus_dirent_init(void)
{
	int rc;
	WRITE_ONCE(prefilter, false);
	sd_fget = (void *)find_kernel_symbol_exact("fget");
	sd_ext4_dir_ops = (void *)find_kernel_symbol_exact("ext4_dir_operations");
	sd_f2fs_dir_ops = (void *)find_kernel_symbol_exact("f2fs_dir_operations");
	if (!sd_fget) {
		rc = -ENOENT;
		goto unavailable;
	}
	rc = sd_qualify();
	if (rc)
		goto unavailable;
	if (!sd_ext4_dir_ops && !sd_f2fs_dir_ops) {
		rc = -EOPNOTSUPP;
		goto unavailable;
	}
	rc = register_kretprobe(&sd_return_probe);
	if (rc)
		goto unavailable;
	sd_return_installed = true;
	sd_post_probe.addr = (void *)(sd_iterate_address + SD_POST_OFFSET);
	rc = register_kprobe(&sd_post_probe);
	if (rc)
		goto rollback;
	sd_post_installed = true;
	sd_call_probe.addr = (void *)(sd_iterate_address + SD_CALL_OFFSET);
	rc = register_kprobe(&sd_call_probe);
	if (rc)
		goto rollback;
	sd_call_installed = true;
	WRITE_ONCE(sd_ready, true);
	WRITE_ONCE(sd_accepting, true);
	SUSFS_LOGI("sus_dirent: native ext4/F2FS actor composition armed\n");
	return 0;
rollback:
	susfs_dirent_stop();
unavailable:
	WRITE_ONCE(sd_qualification_error, rc);
	SUSFS_LOGI("sus_dirent: composed output unavailable (%d), preserving original chain with post-filter\n", rc);
	return 0;
}

void susfs_sus_dirent_exit(void)
{
	WRITE_ONCE(prefilter, false);
	susfs_dirent_stop();
}
