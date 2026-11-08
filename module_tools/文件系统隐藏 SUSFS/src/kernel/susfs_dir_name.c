// SPDX-License-Identifier: GPL-2.0-only
/* Name rules consult actual lookup aliases. The inode-only directory fallback
 * does not pin every matching inode or resolve paths again inside VFS hooks. */
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/string.h>

#include "skp_policy_adapter.h"
#include "susfs.h"
#include "susfs_dir_name.h"
#include "symbol_resolver.h"

static struct dentry *(*directory_find_alias)(struct inode *);

int susfs_directory_names_init(void)
{
    unsigned long address = find_kernel_symbol_exact("d_find_alias");

    /* Exact builtin resolution excludes another module's function. Missing
     * support disables this mode without affecting existing path rules. */
    WRITE_ONCE(directory_find_alias, (void *)address);
    return address ? 0 : -EOPNOTSUPP;
}

bool susfs_directory_names_ready(void)
{
    return READ_ONCE(directory_find_alias) != NULL;
}

/* Live kernel CFI type ids may differ from this build. Follow the fixed,
 * by-name kernel trampolines; only the exact builtin address is admitted. */
static __nocfi noinline struct dentry *susfs_directory_find_alias(struct inode *inode)
{
    struct dentry *(*lookup)(struct inode *) = READ_ONCE(directory_find_alias);

    return lookup ? lookup(inode) : NULL;
}

static bool susfs_directory_name_copy(char *destination, const char *name,
                                      int length)
{
    /* Check length before inspecting a possibly malformed actor pointer. */
    if (!name || length <= 0 || length > NAME_MAX ||
        memchr(name, '\0', length) || memchr(name, '/', length) ||
        (length == 1 && name[0] == '.') ||
        (length == 2 && name[0] == '.' && name[1] == '.'))
        return false;
    memcpy(destination, name, length);
    destination[length] = '\0';
    return true;
}

bool susfs_directory_entry_hidden(const char *name, int namlen,
                                  unsigned int type)
{
    char terminated[NAME_MAX + 1];

    if ((type != DT_DIR && type != DT_REG) || !susfs_directory_names_ready() ||
        !sus_path_group_supported() || !skp_policy_directory_names_present() ||
        !susfs_directory_name_copy(terminated, name, namlen))
        return false;
    return skp_policy_directory_name_hidden(terminated);
}

static bool susfs_name_dentry_matches(const struct dentry *dentry,
                                      const struct inode *expected)
{
    /* The entry is borrowed; the cast only permits acquiring its d_lock. */
    struct dentry *entry = (struct dentry *)dentry;
    struct inode *inode;
    char name[NAME_MAX + 1];
    unsigned int length;
    bool valid = false, hidden = false;

    if (!entry || !susfs_directory_names_ready() || !sus_path_group_supported() ||
        !skp_policy_directory_names_present())
        return false;

    spin_lock(&entry->d_lock);
    inode = d_inode(entry);
    length = entry->d_name.len;
    if (inode && (!expected || inode == expected) &&
        (S_ISDIR(READ_ONCE(inode->i_mode)) ||
                  S_ISREG(READ_ONCE(inode->i_mode))) &&
        !IS_ROOT(entry) && !(entry->d_flags & DCACHE_DISCONNECTED) &&
        length <= NAME_MAX &&
        susfs_directory_name_copy(name, (const char *)entry->d_name.name,
                                  (int)length)) {
        valid = true;
    }
    spin_unlock(&entry->d_lock);

    /* Match only the bounded snapshot, outside the dentry lock. A concurrent
     * rename moves the next decision to its new name, without an inode cache. */
    if (valid)
        hidden = skp_policy_directory_name_hidden(name);
    return hidden;
}

bool susfs_name_dentry_hidden(const struct dentry *dentry)
{
    return susfs_name_dentry_matches(dentry, NULL);
}

bool susfs_directory_inode_hidden(struct inode *inode)
{
    struct dentry *alias;
    bool hidden;

    if (!inode || !S_ISDIR(READ_ONCE(inode->i_mode)) ||
        !susfs_directory_names_ready() || !sus_path_group_supported() ||
        (!skp_policy_directory_names_present() && !skp_policy_path_contents_present()))
        return false;

    /* d_find_alias returns a referenced alias. Directories cannot have ordinary
     * hard links, so their connected alias identifies their current basename.
     * Regular inodes deliberately never enter this fallback. */
    alias = susfs_directory_find_alias(inode);
    if (!alias)
        return false;
    hidden = susfs_name_dentry_matches(alias, inode) ||
             skp_policy_path_contents_hidden(alias, false);
    dput(alias);
    return hidden;
}
