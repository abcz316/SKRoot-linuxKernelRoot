/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_FULL_OBJECTS_H
#define SUSFS_SKP_FULL_OBJECTS_H
#include "skp_group_objects.h"

#define SKP_FULL_OBJECTS_VERSION 1U
#define SKP_GROUP_REDIRECTS_MAX 64U
#define SKP_GROUP_MOUNTS_MAX 64U
#define SKP_MOUNT_CHAIN_MAX 32U

struct skp_redirect_key {
	skp_subject_u64 dev;
	skp_subject_u64 ino;
	skp_subject_u32 igen;
	skp_subject_u32 reserved;
};
struct skp_group_redirect_object {
	skp_subject_u32 profile_id;
	skp_subject_u32 reserved;
	struct skp_redirect_key source;
	struct skp_redirect_key target;
	skp_subject_u64 source_mnt_id;
	skp_subject_u64 target_mnt_id;
};

enum skp_redirect_direction {
	SKP_REDIRECT_FORWARD = 0,
	SKP_REDIRECT_REVERSE = 1,
	SKP_REDIRECT_IDS = 2
};
struct skp_mount_query_result {
	skp_subject_u32 hidden;
	skp_subject_u32 legacy_allowed;
	skp_subject_u64 shown_id;
	skp_subject_u64 parent_id;
	skp_subject_u32 uncertain;
	skp_subject_u32 reserved;
};
struct skp_fdinfo_query_result {
	skp_subject_u32 legacy_allowed;
	skp_subject_u32 rewrite_ino;
	skp_subject_u64 ino;
	skp_subject_u64 mnt_id;
};

#endif
