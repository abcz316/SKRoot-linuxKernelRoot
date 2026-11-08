/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SUSFS_DIRENT_H
#define SUSFS_DIRENT_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>

struct task_struct;
struct susfs_dirent_guard;

/* Caller-owned storage, live around exactly one call to the saved syscall.
 * file is separately held by the caller. Never inspect a retired ctx in end. */
struct susfs_dirent_call {
	struct hlist_node node;
	struct task_struct *task;
	struct file *file;
	struct susfs_dirent_guard *guard;
	struct dir_context *bound_ctx;
	filldir_t original_actor;
	unsigned long bound_sp;
	unsigned int iterations;
	unsigned int attached;
	unsigned int restored;
	unsigned int callbacks;
	unsigned long call_missed;
	unsigned long post_missed;
	int return_missed;
	bool active;
	bool bound;
	bool failed;
};

/* False means explicit post-filter fallback; the call object is still safe
 * to pass to end. Native, qualified ext4/F2FS calls are the initial scope. */
bool susfs_dirent_begin(struct susfs_dirent_call *call, struct file *file, bool compat);
/* True only when the complete single iterator was composed and restored. */
bool susfs_dirent_end(struct susfs_dirent_call *call);
bool susfs_dirent_composed_ready(void);
int susfs_dirent_status_json(char *buffer, size_t capacity);
int susfs_dirent_stat_line(char *buffer, size_t capacity);
/* Idempotent, called before syscall wrapper teardown or by layer exit. */
void susfs_dirent_stop(void);

#endif
