/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_DIR_NAME_H
#define SUSFS_DIR_NAME_H

#include <linux/types.h>

struct inode;
struct dentry;

/* Failure disables only directory-name rules; ordinary PATH rules keep their
 * existing object identities and routes. Call once before publishing rules. */
int susfs_directory_names_init(void);
bool susfs_directory_names_ready(void);

/* Names supplied by a filesystem actor or a validated dirent record are length
 * delimited. Only ordinary files and directories match this rule mode. */
bool susfs_directory_entry_hidden(const char *name, int namlen,
                                  unsigned int type);

/* Evaluate the actual lookup alias, so a regular file's differently named hard
 * link remains independently visible. The caller retains the dentry reference.
 * The helper takes only its d_lock and does not acquire/release references. */
bool susfs_name_dentry_hidden(const struct dentry *dentry);

/* The caller owns the inode and must be in ref-walk context: acquiring and
 * dropping its directory alias is not valid for MAY_NOT_BLOCK permission walks.
 * Only directories use this inode-only route. Regular files require the actual
 * lookup dentry above, since they can have differently named hard links.
 * No alias or inode reference is retained across calls. */
bool susfs_directory_inode_hidden(struct inode *inode);

#endif
