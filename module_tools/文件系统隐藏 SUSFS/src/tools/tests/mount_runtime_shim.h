/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_MOUNT_RUNTIME_SHIM_H
#define SUSFS_SKP_MOUNT_RUNTIME_SHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define __nocfi
#define noinline __attribute__((noinline))
#define GFP_KERNEL 1U
#define LOOKUP_FOLLOW 2U
#define READ_ONCE(x) (x)
typedef struct { unsigned int sequence; } seqcount_t;
typedef struct { bool locked; struct { seqcount_t seqcount; } seqcount; } seqlock_t;
#define smp_rmb() ((void)0)
struct dentry { unsigned int references; };
struct mnt_namespace { unsigned int references; };
struct vfsmount { struct dentry *mnt_root; unsigned int references; };
struct mount {
	struct vfsmount mnt;
	struct mount *mnt_parent;
	struct mnt_namespace *mnt_ns;
	int mnt_id;
};
struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct fs_struct { struct { seqcount_t seqcount; } seq; struct path root; };
struct nsproxy { struct mnt_namespace *mnt_ns; };
struct task_struct { struct nsproxy *nsproxy; struct fs_struct *fs; };
extern struct task_struct *current;
static inline struct mount *real_mount(struct vfsmount *mount)
{
	return (struct mount *)((char *)mount - offsetof(struct mount, mnt));
}
void *kvzalloc(size_t size, unsigned int flags);
void kvfree(const void *pointer);
int kern_path(const char *name, unsigned int flags, struct path *path);
void path_put(const struct path *path);
struct vfsmount *mntget(struct vfsmount *mount);
void mntput(struct vfsmount *mount);
void get_mnt_ns(struct mnt_namespace *ns);
void get_fs_root(struct fs_struct *fs, struct path *path);
unsigned long find_kernel_symbol_exact(const char *name);
void read_seqlock_excl(seqlock_t *lock);
void read_sequnlock_excl(seqlock_t *lock);
unsigned int raw_read_seqcount(const seqcount_t *counter);
bool read_seqcount_retry(const seqcount_t *counter, unsigned int sequence);
#endif
