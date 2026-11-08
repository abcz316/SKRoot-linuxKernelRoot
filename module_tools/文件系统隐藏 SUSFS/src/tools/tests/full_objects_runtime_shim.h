/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_FULL_OBJECTS_RUNTIME_SHIM_H
#define SUSFS_FULL_OBJECTS_RUNTIME_SHIM_H
#include "group_paths_runtime_shim.h"
#include "../../kernel/skp_full_objects.h"
#include <stddef.h>
#include <errno.h>
struct kstatfs {
	long f_type, f_bsize;
	u64 f_blocks, f_bfree, f_bavail, f_files, f_ffree;
	struct { int val[2]; } f_fsid;
	long f_namelen, f_frsize, f_flags, f_spare[4];
};
struct mount { struct vfsmount mnt; int mnt_id; };
#define real_mount(p) ((struct mount *)((char *)(p) - offsetof(struct mount, mnt)))
void mntput(struct vfsmount *mnt);
int susfs_open_redirect_resolve_group(const char *source, const char *target,
		struct skp_group_redirect_object *object, struct kstatfs *statfs,
		struct vfsmount **source_mnt, struct vfsmount **target_mnt);
#endif
