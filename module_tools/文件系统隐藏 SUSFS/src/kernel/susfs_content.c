// SPDX-License-Identifier: GPL-2.0
/*
 * Read-only content replacement. The caller opens A with the full namei/VFS/LSM
 * path. Only its read operations are replaced; f_path, inode, mapping, cred,
 * security and the filesystem's private_data continue to belong to A.
 *
 * Reviewed against android16-6.12: proc/cpuinfo.c, proc/meminfo.c,
 * proc/version.c, uptime.c, loadavg.c, stat.c, cmdline.c, bootconfig.c and
 * arm64/kernel/cpuinfo.c. These root proc entries do not perform additional
 * reader authorization in their seq show callbacks. Other sources must use
 * audited standard ext4/F2FS/tmpfs/EROFS fops and have no fscrypt, fs-verity or
 * DAX state. Expanding either class requires reviewing its read callbacks.
 */
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include "internal.h"
#include "lsm_hook.h"
#include "skp_policy_adapter.h"
#include "symbol_resolver.h"
#include "susfs.h"
#include "susfs_content.h"
#include "susfs_log.h"
#include "susfs_or_entry.h"

#define CONTENT_MAX_BYTES (1024UL * 1024)
#define CONTENT_TOTAL_BYTES (8UL * 1024 * 1024)
#define CONTENT_READ_CHUNK (64UL * 1024)
#define CONTENT_SOURCE_REGULAR 9
#define CONTENT_SAFE_FLAGS (O_CLOEXEC | O_LARGEFILE | O_NOFOLLOW | \
			    O_NONBLOCK | O_NDELAY | O_NOCTTY | O_NOATIME | O_DIRECTORY)

struct susfs_content {
	refcount_t refs;
	size_t allocation;
	size_t size;
	unsigned int source_kind;
	dev_t source_dev;
	unsigned long source_ino;
	u32 source_generation;
	u8 data[];
};

/* The original filesystem state, including proc seq_file, stays in private_data. */
struct content_file {
	struct hlist_node node;
	struct file *file;
	const struct file_operations *original;
	struct susfs_content *content;
};

/* Stack storage is safe because it remains linked only during do_filp_open().
 * A per-task LIFO and one-shot consumption exclude nested/unrelated opens. */
struct content_open_guard {
	struct hlist_node node;
	struct task_struct *task;
	const struct path *expected;
	bool consumed;
};

static DEFINE_HASHTABLE(content_files, 8);
static DEFINE_HASHTABLE(content_guards, 6);
static DEFINE_SPINLOCK(content_file_lock);
static DEFINE_SPINLOCK(content_guard_lock);
static atomic_long_t content_allocated = ATOMIC_LONG_INIT(0);
static bool content_enabled;

static int (*content_build_open_flags_fn)(const struct open_how *, struct open_flags *);
static struct file *(*content_do_filp_open_fn)(int, struct filename *, const struct open_flags *);
static struct file *(*content_filp_open_fn)(const char *, int, umode_t);
static ssize_t (*content_kernel_read_fn)(struct file *, void *, size_t, loff_t *);
static loff_t (*content_fixed_size_llseek_fn)(struct file *, loff_t, int, loff_t);
static size_t (*content_copy_to_iter_fn)(const void *, size_t, struct iov_iter *);
static struct file *(*content_fget_raw_fn)(unsigned int);
static const struct file_operations *content_ext4_fops;
static const struct file_operations *content_f2fs_fops;
static const struct file_operations *content_tmpfs_fops;
static const struct file_operations *content_erofs_fops;

static int content_file_open(struct file *file);
static struct ksu_lsm_hook content_open_hook =
	KSU_LSM_HOOK_INSERT(file_open, content_file_open);
static_assert(__builtin_types_compatible_p(
	typeof(((union security_list_options *)0)->file_open),
	typeof(&content_file_open)), "content file_open hook signature mismatch");

/* By-name calls and calls to the kernel-owned original fops must stay out of
 * CFI-instrumented indirect sites. The callbacks themselves keep their hashes. */
static __nocfi noinline int content_build_open_flags(const struct open_how *how,
						    struct open_flags *op)
{
	return content_build_open_flags_fn(how, op);
}

static __nocfi noinline struct file *content_do_filp_open(int dfd,
		struct filename *name, const struct open_flags *op)
{
	return content_do_filp_open_fn(dfd, name, op);
}

static __nocfi noinline struct file *content_filp_open(const char *name)
{
	return content_filp_open_fn(name, O_RDONLY | O_LARGEFILE | O_NONBLOCK | O_NOFOLLOW, 0);
}

static __nocfi noinline ssize_t content_kernel_read(struct file *file,
				void *buffer, size_t count, loff_t *pos)
{
	return content_kernel_read_fn(file, buffer, count, pos);
}

static __nocfi noinline loff_t content_fixed_size_llseek(struct file *file,
					loff_t offset, int whence, loff_t size)
{
	return content_fixed_size_llseek_fn(file, offset, whence, size);
}

static __nocfi noinline size_t content_copy_to_iter(const void *data,
					 size_t bytes, struct iov_iter *iter)
{
	return content_copy_to_iter_fn(data, bytes, iter);
}

static __nocfi noinline struct file *content_fget_raw(unsigned int fd)
{
	return content_fget_raw_fn(fd);
}

static __nocfi noinline int content_original_release(
		const struct file_operations *ops, struct inode *inode, struct file *file)
{
	return ops->release ? ops->release(inode, file) : 0;
}

static __nocfi noinline int content_original_flush(
		const struct file_operations *ops, struct file *file, fl_owner_t owner)
{
	return ops->flush ? ops->flush(file, owner) : 0;
}

static __nocfi noinline int content_original_file_open(struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	typeof(((union security_list_options *)0)->file_open) original;

	/* Paired with lsm_hook.c's publication before replacing the static call. */
	smp_rmb();
	original = (typeof(original))READ_ONCE(content_open_hook.original);
	if (original)
		return original(file);
#endif
	return 0;
}

static unsigned int content_source_name(const char *source)
{
	if (!strcmp(source, "/proc/cpuinfo"))
		return 1;
	if (!strcmp(source, "/proc/meminfo"))
		return 2;
	if (!strcmp(source, "/proc/version"))
		return 3;
	if (!strcmp(source, "/proc/uptime"))
		return 4;
	if (!strcmp(source, "/proc/loadavg"))
		return 5;
	if (!strcmp(source, "/proc/stat"))
		return 6;
	if (!strcmp(source, "/proc/cmdline"))
		return 7;
	if (!strcmp(source, "/proc/bootconfig"))
		return 8;
	return 0;
}

static bool content_regular_routes_ready(void)
{
	/* Native newfstatat, fstat and statx must all report the content size. */
	return content_fget_raw_fn && sus_path_group_watch_ready() &&
	       (susfs_kstat_group_routes() & 7U) == 7U;
}

static const struct file_operations *content_regular_ops(const struct inode *inode)
{
	const struct file_operations *ops;

	if (!content_regular_routes_ready() || !inode ||
	    !S_ISREG(inode->i_mode) || IS_ENCRYPTED(inode) ||
	    IS_VERITY(inode) || IS_DAX(inode))
		return NULL;
	switch (inode->i_sb->s_magic) {
	case EXT4_SUPER_MAGIC:
		ops = content_ext4_fops;
		break;
	case F2FS_SUPER_MAGIC:
		ops = content_f2fs_fops;
		break;
	case TMPFS_MAGIC:
		ops = content_tmpfs_fops;
		break;
	case EROFS_SUPER_MAGIC_V1:
		ops = content_erofs_fops;
		break;
	default:
		return NULL;
	}
	/* A filesystem magic identifies a format, not the per-inode operations.
	 * Reject alternate or interposed fops even on one of the four filesystems. */
	return ops && inode->i_fop == ops ? ops : NULL;
}

static unsigned int content_source_path(const struct path *path)
{
	struct dentry *dentry;
	struct inode *inode;
	const struct qstr *name;

	if (!path || !(dentry = path->dentry) || !(inode = d_inode(dentry)) ||
	    !S_ISREG(inode->i_mode))
		return 0;
	if (inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return content_regular_ops(inode) ? CONTENT_SOURCE_REGULAR : 0;
	if (dentry->d_parent != inode->i_sb->s_root)
		return 0;
	name = &dentry->d_name;
	if (name->len == 7 && !memcmp(name->name, "cpuinfo", 7))
		return 1;
	if (name->len == 7 && !memcmp(name->name, "meminfo", 7))
		return 2;
	if (name->len == 7 && !memcmp(name->name, "version", 7))
		return 3;
	if (name->len == 6 && !memcmp(name->name, "uptime", 6))
		return 4;
	if (name->len == 7 && !memcmp(name->name, "loadavg", 7))
		return 5;
	if (name->len == 4 && !memcmp(name->name, "stat", 4))
		return 6;
	if (name->len == 7 && !memcmp(name->name, "cmdline", 7))
		return 7;
	if (name->len == 10 && !memcmp(name->name, "bootconfig", 10))
		return 8;
	return 0;
}

static bool content_same_inode(const struct path *a, const struct path *b)
{
	struct inode *ia = d_inode(a->dentry);
	struct inode *ib = d_inode(b->dentry);

	return ia && ib && ia->i_sb->s_dev == ib->i_sb->s_dev &&
	       ia->i_ino == ib->i_ino && ia->i_generation == ib->i_generation;
}

bool susfs_content_matches_source(const struct susfs_content *content,
				  const struct path *path)
{
	struct inode *inode;

	if (!content || !path || !path->dentry ||
	    content_source_path(path) != content->source_kind)
		return false;
	inode = d_inode(path->dentry);
	return inode->i_sb->s_dev == content->source_dev &&
	       inode->i_ino == content->source_ino &&
	       inode->i_generation == content->source_generation;
}

static bool content_target_allowed(const struct path *path)
{
	struct inode *inode = d_inode(path->dentry);

	if (!inode || !S_ISREG(inode->i_mode))
		return false;
	switch (inode->i_sb->s_magic) {
	case EXT4_SUPER_MAGIC:
	case F2FS_SUPER_MAGIC:
	case TMPFS_MAGIC:
	case EROFS_SUPER_MAGIC_V1:
	case FUSE_SUPER_MAGIC:
		return true;
	default:
		return false;
	}
}

static bool content_reserve(size_t allocation)
{
	long old = atomic_long_read(&content_allocated);

	for (;;) {
		long observed;

		if (old < 0 || old > CONTENT_TOTAL_BYTES - allocation)
			return false;
		observed = atomic_long_cmpxchg(&content_allocated, old, old + allocation);
		if (observed == old)
			return true;
		old = observed;
	}
}

bool susfs_content_ready(void)
{
	return READ_ONCE(content_enabled);
}

unsigned long susfs_content_bytes(void)
{
	return atomic_long_read(&content_allocated);
}

unsigned int susfs_content_regular_filesystems(void)
{
	if (!susfs_content_ready() || !content_regular_routes_ready())
		return 0;
	return (content_ext4_fops ? SUSFS_CONTENT_FS_EXT4 : 0) |
	       (content_f2fs_fops ? SUSFS_CONTENT_FS_F2FS : 0) |
	       (content_tmpfs_fops ? SUSFS_CONTENT_FS_TMPFS : 0) |
	       (content_erofs_fops ? SUSFS_CONTENT_FS_EROFS : 0);
}

unsigned long susfs_content_size(const struct susfs_content *content)
{
	return content ? content->size : 0;
}

bool susfs_content_is_regular(const struct susfs_content *content)
{
	return content && content->source_kind == CONTENT_SOURCE_REGULAR;
}

void susfs_content_get(struct susfs_content *content)
{
	if (content)
		refcount_inc(&content->refs);
}

void susfs_content_put(struct susfs_content *content)
{
	size_t allocation;

	if (!content || !refcount_dec_and_test(&content->refs))
		return;
	allocation = content->allocation;
	vfree(content);
	atomic_long_sub(allocation, &content_allocated);
}

int susfs_content_prepare(const char *source, const char *target,
			  struct susfs_content **out)
{
	struct path source_path, target_path;
	struct susfs_content *content = NULL;
	struct file *file;
	loff_t size, pos = 0;
	size_t allocation, capacity;
	unsigned int kind;
	dev_t source_dev;
	unsigned long source_ino;
	u32 source_generation;
	int rc;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!susfs_content_ready())
		return -EOPNOTSUPP;
	if (!source || source[0] != '/' || !target || target[0] != '/')
		return -EOPNOTSUPP;
	rc = kern_path(source, LOOKUP_FOLLOW, &source_path);
	if (rc)
		return rc;
	kind = content_source_path(&source_path);
	rc = kind && (kind == CONTENT_SOURCE_REGULAR ||
		content_source_name(source) == kind) ? 0 : -EOPNOTSUPP;
	if (rc) {
		path_put(&source_path);
		return rc;
	}
	source_dev = d_inode(source_path.dentry)->i_sb->s_dev;
	source_ino = d_inode(source_path.dentry)->i_ino;
	source_generation = d_inode(source_path.dentry)->i_generation;
	path_put(&source_path);
	rc = kern_path(target, LOOKUP_FOLLOW, &target_path);
	if (rc)
		return rc;
	if (!content_target_allowed(&target_path)) {
		rc = -EOPNOTSUPP;
		goto put_target;
	}
	file = content_filp_open(target);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		goto put_target;
	}
	if (!content_target_allowed(&file->f_path) ||
	    !content_same_inode(&target_path, &file->f_path)) {
		rc = -ESTALE;
		goto put_file;
	}
	size = i_size_read(file_inode(file));
	if (size < 0 || size > CONTENT_MAX_BYTES) {
		rc = -EFBIG;
		goto put_file;
	}
	/* An extra byte proves EOF instead of silently clipping a growing file.
 * Charge page-rounded storage, including headers, until the final old FD closes. */
	capacity = (size_t)size + 1;
	allocation = PAGE_ALIGN(sizeof(*content) + capacity);
	if (!content_reserve(allocation)) {
		rc = -ENOSPC;
		goto put_file;
	}
	content = vzalloc(allocation);
	if (!content) {
		atomic_long_sub(allocation, &content_allocated);
		rc = -ENOMEM;
		goto put_file;
	}
	refcount_set(&content->refs, 1);
	content->allocation = allocation;
	content->source_kind = kind;
	content->source_dev = source_dev;
	content->source_ino = source_ino;
	content->source_generation = source_generation;
	while (pos < capacity) {
		ssize_t got = content_kernel_read(file, content->data + pos,
			min_t(size_t, CONTENT_READ_CHUNK, capacity - pos), &pos);

		if (got < 0) {
			rc = got;
			goto put_content;
		}
		if (!got)
			break;
	}
	if (pos != size || i_size_read(file_inode(file)) != size) {
		rc = -EAGAIN;
		goto put_content;
	}
	content->size = pos;
	*out = content;
	rc = 0;
	goto put_file;
put_content:
	susfs_content_put(content);
put_file:
	fput(file);
put_target:
	path_put(&target_path);
	return rc;
}

static struct susfs_content *content_for_file(struct file *file)
{
	struct content_file *entry;
	struct susfs_content *content = NULL;
	unsigned long irqflags;

	spin_lock_irqsave(&content_file_lock, irqflags);
	hash_for_each_possible(content_files, entry, node, (unsigned long)file) {
		if (entry->file == file) {
			content = entry->content;
			susfs_content_get(content);
			break;
		}
	}
	spin_unlock_irqrestore(&content_file_lock, irqflags);
	return content;
}

bool susfs_content_fd_size(unsigned int fd, u64 ino, u64 dev, unsigned long *size)
{
	struct susfs_content *content;
	struct inode *inode;
	struct file *file;
	bool found = false;

	if (!size || !content_fget_raw_fn)
		return false;
	file = content_fget_raw(fd);
	if (!file)
		return false;
	inode = file_inode(file);
	if (!inode || (u64)inode->i_ino != ino || (u64)inode->i_sb->s_dev != dev)
		goto put_file;
	content = content_for_file(file);
	if (content) {
		if (susfs_content_is_regular(content)) {
			*size = susfs_content_size(content);
			found = true;
		}
		susfs_content_put(content);
	}
put_file:
	fput(file);
	return found;
}

static ssize_t content_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct susfs_content *content;
	size_t count, copied;
	ssize_t result;

	if (iocb->ki_pos < 0)
		return -EINVAL;
	if (iocb->ki_flags & (IOCB_DIRECT | IOCB_NOWAIT | IOCB_HIPRI | IOCB_WRITE))
		return -EOPNOTSUPP;
	content = content_for_file(iocb->ki_filp);
	if (!content)
		return -EIO;
	if (iocb->ki_pos >= content->size || !iov_iter_count(iter)) {
		result = 0;
		goto out;
	}
	count = min_t(size_t, iov_iter_count(iter), content->size - iocb->ki_pos);
	copied = content_copy_to_iter(content->data + iocb->ki_pos, count, iter);
	iocb->ki_pos += copied;
	result = copied ? copied : -EFAULT;
out:
	susfs_content_put(content);
	return result;
}

static loff_t content_llseek(struct file *file, loff_t offset, int whence)
{
	struct susfs_content *content = content_for_file(file);
	loff_t result;

	if (!content)
		return -EIO;
	result = content_fixed_size_llseek(file, offset, whence, content->size);
	susfs_content_put(content);
	return result;
}

static int content_flush(struct file *file, fl_owner_t owner)
{
	struct content_file *entry;
	const struct file_operations *original = NULL;
	unsigned long irqflags;

	/* filp_close() owns a file reference throughout ->flush, so release cannot
	 * remove this entry or its original-fops owner while the callback runs. */
	spin_lock_irqsave(&content_file_lock, irqflags);
	hash_for_each_possible(content_files, entry, node, (unsigned long)file) {
		if (entry->file == file) {
			original = entry->original;
			break;
		}
	}
	spin_unlock_irqrestore(&content_file_lock, irqflags);
	return original ? content_original_flush(original, file, owner) : -EIO;
}

static int content_release(struct inode *inode, struct file *file)
{
	struct content_file *entry, *found = NULL;
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave(&content_file_lock, irqflags);
	hash_for_each_possible(content_files, entry, node, (unsigned long)file) {
		if (entry->file == file) {
			hash_del(&entry->node);
			found = entry;
			break;
		}
	}
	spin_unlock_irqrestore(&content_file_lock, irqflags);
	if (WARN_ON_ONCE(!found))
		return 0;
	rc = content_original_release(found->original, inode, file);
	fops_put(found->original);
	susfs_content_put(found->content);
	kfree(found);
	/* __fput still dereferences file->f_op and drops its owner after release.
 * Keep the static wrapper installed; never free a per-file fops here. */
	return rc;
}

static const struct file_operations content_fops = {
	.owner = THIS_MODULE,
	.read_iter = content_read_iter,
	.llseek = content_llseek,
	.flush = content_flush,
	.release = content_release,
};

static bool content_consume_guard(struct file *file)
{
	struct content_open_guard *guard;
	unsigned long irqflags;
	bool allowed = false;

	spin_lock_irqsave(&content_guard_lock, irqflags);
	hash_for_each_possible(content_guards, guard, node, (unsigned long)current) {
		if (guard->task != current)
			continue;
		/* Only the innermost guard belongs to this open, even if it fails. */
		if (!guard->consumed &&
		    file->f_path.mnt == guard->expected->mnt &&
		    file->f_path.dentry == guard->expected->dentry &&
		    content_same_inode(&file->f_path, guard->expected) &&
		    content_source_path(&file->f_path)) {
			guard->consumed = true;
			allowed = true;
		}
		break;
	}
	spin_unlock_irqrestore(&content_guard_lock, irqflags);
	return allowed;
}

static int content_file_open(struct file *file)
{
	bool guarded = content_consume_guard(file);
	int rc = content_original_file_open(file);

	if (rc)
		return rc;
	/* One file_open slot owns both checks. Registering a second INSERT hook
	 * would conflict with the existing 6.12 static-call slot. Check the real
	 * dentry so other names of a hard-linked regular file remain independent. */
	if (sus_path_name_dentry_hidden(file->f_path.dentry))
		return -ENOENT;
	/* io_uring OPENAT, open_by_handle_at and other non-entry routes must never
 * silently open the real source when a content rule applies to this task. */
	if (!guarded && skp_policy_content_source_applies(&file->f_path))
		return -EOPNOTSUPP;
	return 0;
}

bool susfs_content_file_open_ready(void)
{
	return READ_ONCE(content_open_hook.entry) != NULL;
}

const char *susfs_content_disabled_reason(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
	return "kernel_6_6_disabled";
#else
	return "";
#endif
}

struct file *susfs_content_open(int dfd, struct filename *name,
		unsigned long flags, unsigned long mode, unsigned long resolve,
		const struct path *matched_path, struct susfs_content *content)
{
	struct content_open_guard guard;
	struct content_file *entry;
	struct open_how how = { .flags = flags, .mode = mode, .resolve = resolve };
	struct open_flags op;
	struct file *file;
	unsigned long irqflags;
	int rc;

	if (!susfs_content_ready() || !content || !matched_path)
		return ERR_PTR(-EOPNOTSUPP);
	if ((flags & O_ACCMODE) != O_RDONLY || (flags & ~CONTENT_SAFE_FLAGS))
		return ERR_PTR(-EOPNOTSUPP);
	if (!susfs_content_matches_source(content, matched_path))
		return ERR_PTR(-ESTALE);
	/* Pin before allocation or namei can sleep. A blocked source open already
	 * owns module code and a live guard, even though no replacement FD exists.
	 * Success transfers this same reference to content_fops for __fput. */
	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENODEV);
	rc = content_build_open_flags(&how, &op);
	if (rc)
		goto put_module;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		rc = -ENOMEM;
		goto put_module;
	}
	guard.task = current;
	guard.expected = matched_path;
	guard.consumed = false;
	spin_lock_irqsave(&content_guard_lock, irqflags);
	hash_add(content_guards, &guard.node, (unsigned long)current);
	spin_unlock_irqrestore(&content_guard_lock, irqflags);
	file = content_do_filp_open(dfd, name, &op);
	spin_lock_irqsave(&content_guard_lock, irqflags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(&content_guard_lock, irqflags);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		goto free_entry;
	}
	if (!guard.consumed || !content_same_inode(matched_path, &file->f_path) ||
	    !susfs_content_matches_source(content, &file->f_path)) {
		rc = -ESTALE;
		goto put_file;
	}
	/* ->open is allowed to replace f_op. Only the audited standard table may
	 * survive for ordinary files, even when the inode started with that table. */
	if (susfs_content_is_regular(content) &&
	    file->f_op != content_regular_ops(file_inode(file))) {
		rc = -EOPNOTSUPP;
		goto put_file;
	}
	entry->file = file;
	entry->original = file->f_op;
	entry->content = content;
	susfs_content_get(content);
	spin_lock_irqsave(&content_file_lock, irqflags);
	hash_add(content_files, &entry->node, (unsigned long)file);
	spin_unlock_irqrestore(&content_file_lock, irqflags);
	/* Transfer the original fops owner reference into entry. __fput owns the
 * wrapper's module reference; release drops only the original reference. */
	file->f_op = &content_fops;
	file->f_mode &= ~(FMODE_WRITE | FMODE_CAN_WRITE | FMODE_PWRITE);
	file->f_mode |= FMODE_READ | FMODE_CAN_READ | FMODE_LSEEK | FMODE_PREAD;
	return file;
put_file:
	fput(file);
free_entry:
	kfree(entry);
put_module:
	module_put(THIS_MODULE);
	return ERR_PTR(rc);
}

int susfs_content_init(void)
{
	const unsigned int native_routes = (1U << SUSFS_OR_ENTRY_OPENAT) |
		(1U << SUSFS_OR_ENTRY_OPENAT2);
	int rc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	/* 6.6 keeps content replacement disabled. Name hiding still needs this
	 * shared file_open check; INSERT continues the existing LSM chain and
	 * never replaces its authorization. No snapshot imports are required. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
	rc = ksu_register_lsm_hook(&content_open_hook);
	if (!rc)
		SUSFS_LOGI("file_open: name checks ready; source-authorized content disabled on 6.6\n");
	return rc;
#else
	return -EOPNOTSUPP;
#endif
#endif
	if ((susfs_or_entry_routes() & native_routes) != native_routes)
		return -EOPNOTSUPP;
	content_build_open_flags_fn = (void *)find_kernel_symbol_exact("build_open_flags");
	content_do_filp_open_fn = (void *)find_kernel_symbol_exact("do_filp_open");
	content_filp_open_fn = (void *)find_kernel_symbol_exact("filp_open");
	content_kernel_read_fn = (void *)find_kernel_symbol_exact("kernel_read");
	content_fixed_size_llseek_fn = (void *)find_kernel_symbol_exact("fixed_size_llseek");
	content_copy_to_iter_fn = (void *)find_kernel_symbol_exact("_copy_to_iter");
	content_fget_raw_fn = (void *)find_kernel_symbol_exact("fget_raw");
	/* These are optional, built-in data symbols. A missing or modular table
	 * disables only that source filesystem, never broadens the admission test. */
	content_ext4_fops = (void *)find_kernel_symbol_exact("ext4_file_operations");
	content_f2fs_fops = (void *)find_kernel_symbol_exact("f2fs_file_operations");
	content_tmpfs_fops = (void *)find_kernel_symbol_exact("shmem_file_operations");
	content_erofs_fops = (void *)find_kernel_symbol_exact("erofs_file_fops");
	if (!content_build_open_flags_fn || !content_do_filp_open_fn ||
	    !content_filp_open_fn || !content_kernel_read_fn ||
	    !content_fixed_size_llseek_fn || !content_copy_to_iter_fn)
		return -ENOENT;
	rc = ksu_register_lsm_hook(&content_open_hook);
	if (rc)
		return rc;
	WRITE_ONCE(content_enabled, true);
	SUSFS_LOGI("content redirect: read-only snapshots ready (regular fs mask=%u)\n",
		   susfs_content_regular_filesystems());
	return 0;
}

void susfs_content_exit(void)
{
	if (!susfs_content_file_open_ready())
		return;
	WRITE_ONCE(content_enabled, false);
	ksu_unregister_lsm_hook(&content_open_hook);
	/* All snapshot FDs pin THIS_MODULE, so a normal unload cannot reach here
 * before their release. Rules are cleared by the caller before exit. */
	WARN_ON_ONCE(!hash_empty(content_files));
	WARN_ON_ONCE(!hash_empty(content_guards));
	WARN_ON_ONCE(atomic_long_read(&content_allocated));
}
