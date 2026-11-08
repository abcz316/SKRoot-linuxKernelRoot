/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_POLICY_ADAPTER_H
#define SUSFS_SKP_POLICY_ADAPTER_H
#include "skp_sequential.h"
#include "skp_full_objects.h"
#define SKP_POLICY_NODE_NAME "susfs_skp_policy"
#define SKP_POLICY_NODE SKP_SEQUENTIAL_NODE
#if defined(__KERNEL__) || defined(SKP_SEQUENTIAL_HOSTTEST)
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/statfs.h>
#endif
struct inode;
struct dentry;
struct super_block;
struct path;
struct susfs_content;
void skp_policy_release_superblock(struct super_block *sb);
struct skp_redirect_query_result {
 u32 matched, legacy_allowed;
 char path[SKP_GROUP_PATH_LEN], target_path[SKP_GROUP_PATH_LEN];
 u64 source_dev, source_ino, source_mnt_id;
 struct kstatfs source_statfs;
};
bool skp_policy_override(bool *applies);
bool skp_policy_paths_inode_override(struct inode *inode, bool *hidden);
bool skp_policy_paths_dirent_override(u64 dev, u64 ino, const char *name, bool *hidden);
bool skp_policy_paths_active(void);
bool skp_policy_paths_present(void);
bool skp_policy_directory_names_present(void);
bool skp_policy_path_contents_present(void);
/* Existing directory permission hook: deny searching below a matched anchor. */
bool skp_policy_path_contents_search_hidden(struct inode *inode);
/* include_self is only for enumerating the directory itself. Access checks
 * exclude the anchor so the selected directory remains usable. */
bool skp_policy_path_contents_hidden(const struct dentry *dentry, bool include_self);
bool skp_policy_directory_name_hidden(const char *name);
bool skp_policy_redirects_active(void);
/* Content rules never participate in B-to-A reverse path spoofing. The get
 * result owns one payload reference; the caller releases it after opening. */
struct susfs_content *skp_policy_content_get(const struct path *path);
bool skp_policy_content_source_applies(const struct path *path);
bool skp_policy_content_stat_size(u64 dev, u64 ino, u64 *size);
bool skp_policy_mount_path_hidden(const char *path, const char *devname);
bool skp_policy_mounts_active(void);
enum skp_object_query_mode skp_policy_kstat_query(u64 dev, u64 ino, struct skp_kstat_query_result *result);
enum skp_object_query_mode skp_policy_kstat_maps_query(u64 dev, u64 ino, u32 igen, struct skp_kstat_query_result *result);
enum skp_object_query_mode skp_policy_map_query(u64 dev, u64 ino, struct skp_map_query_result *result);
enum skp_object_query_mode skp_policy_redirect_query(u64 dev, u64 ino, u32 igen, u64 mnt_id, u32 direction, struct skp_redirect_query_result *result);
enum skp_object_query_mode skp_policy_mount_query(u64 cookie, u64 id, u64 parent_id, struct skp_mount_query_result *result);
enum skp_object_query_mode skp_policy_fdinfo_query(u64 ino, u64 mnt_id, struct skp_fdinfo_query_result *result);
int skp_policy_adapter_init(void);
void skp_policy_adapter_exit(void);
#endif
#endif
