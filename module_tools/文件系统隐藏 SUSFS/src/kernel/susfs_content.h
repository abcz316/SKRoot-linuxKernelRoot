/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SUSFS_CONTENT_H
#define _SUSFS_CONTENT_H

#ifndef SKP_SEQUENTIAL_HOSTTEST
#include <linux/types.h>
#endif

struct file;
struct filename;
struct path;
struct susfs_content;

int susfs_content_init(void);
void susfs_content_exit(void);
bool susfs_content_ready(void);
bool susfs_content_file_open_ready(void);
const char *susfs_content_disabled_reason(void);
unsigned long susfs_content_bytes(void);
#define SUSFS_CONTENT_FS_EXT4  (1U << 0)
#define SUSFS_CONTENT_FS_F2FS  (1U << 1)
#define SUSFS_CONTENT_FS_TMPFS (1U << 2)
#define SUSFS_CONTENT_FS_EROFS (1U << 3)
/* Only filesystems whose standard, built-in fops were resolved are advertised. */
unsigned int susfs_content_regular_filesystems(void);
unsigned long susfs_content_size(const struct susfs_content *content);
bool susfs_content_is_regular(const struct susfs_content *content);
/* The caller's current FD must still resolve to the stat result's identity. */
bool susfs_content_fd_size(unsigned int fd, u64 ino, u64 dev, unsigned long *size);
/* Success transfers one reference to the caller. No policy lock may be held. */
int susfs_content_prepare(const char *source, const char *target,
			  struct susfs_content **out);
void susfs_content_get(struct susfs_content *content);
void susfs_content_put(struct susfs_content *content);
bool susfs_content_matches_source(const struct susfs_content *content,
				  const struct path *path);
/* The caller retains its content reference. Success returns an ordinary owned file. */
struct file *susfs_content_open(int dfd, struct filename *name,
			       unsigned long flags, unsigned long mode,
			       unsigned long resolve,
			       const struct path *matched_path,
			       struct susfs_content *content);

#endif
