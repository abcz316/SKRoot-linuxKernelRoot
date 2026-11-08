/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_GROUP_PATHS_RUNTIME_SHIM_H
#define SUSFS_SKP_GROUP_PATHS_RUNTIME_SHIM_H

/* Typed test doubles for the exact VFS calls used by the production resolver.
 * The test compiles kernel/skp_group_paths_runtime.c itself; it never substitutes
 * another resolver implementation. Counts represent references above each
 * fixture's baseline. No task credentials, syscalls or interception are used. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define GFP_KERNEL 0x01U
#define LOOKUP_FOLLOW 0x02U
#define EINVAL 22
#define ENOMEM 12
#define ENOENT 2
#define ESTALE 116
#define ENAMETOOLONG 36
#define EEXIST 17
#define E2BIG 7
#define READ_ONCE(value) (value)

struct super_block {
	u32 s_dev;
#ifdef SKP_POLICY_ADAPTER_HOSTTEST
	unsigned long s_magic;
#endif
};

struct inode {
	struct super_block *i_sb;
	u64 i_ino;
	unsigned int i_mode;
	unsigned int references;
};

struct runtime_test_spinlock {
	bool locked;
};

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct inode *inode;
	struct qstr d_name;
	struct runtime_test_spinlock d_lock;
	unsigned int references;
};

struct vfsmount {
	unsigned int references;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

void *kvzalloc(size_t size, unsigned int flags);
void kvfree(const void *memory);
int kern_path(const char *name, unsigned int flags, struct path *path);
void path_put(const struct path *path);
struct inode *d_inode(const struct dentry *dentry);
struct inode *igrab(struct inode *inode);
void iput(struct inode *inode);
void spin_lock(struct runtime_test_spinlock *lock);
void spin_unlock(struct runtime_test_spinlock *lock);
long strscpy(char *destination, const char *source, size_t capacity);

#endif /* SUSFS_SKP_GROUP_PATHS_RUNTIME_SHIM_H */
