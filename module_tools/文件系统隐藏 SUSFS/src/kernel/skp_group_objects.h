/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_GROUP_OBJECTS_H
#define SUSFS_SKP_GROUP_OBJECTS_H

#include "skp_group_paths.h"
#ifdef __KERNEL__
typedef s64 skp_object_s64;
#else
typedef signed long long skp_object_s64;
#endif

#define SKP_GROUP_OBJECTS_VERSION 1U
#define SKP_GROUP_KSTATS_MAX 32U
#define SKP_GROUP_MAPS_MAX 64U
#define SKP_KSTAT_FLAGS_ALL 4095U

/* DEV is new_encode_dev(), never raw s_dev. Unselected fields and reserved
 * bytes are zero. Masks have the corrected upstream ctime bit (1U << 8).
 * size/blocks are nonnegative, blksize is 1..INT_MAX, ns is < 1000000000.
 * ABI-specific narrowing remains checked by the stat reader. */
struct skp_kstat_values {
	skp_subject_u64 ino;
	skp_subject_u64 dev_encoded;
	skp_subject_u32 nlink;
	skp_subject_u32 flags;
	skp_object_s64 size;
	skp_object_s64 atime_sec;
	skp_object_s64 mtime_sec;
	skp_object_s64 ctime_sec;
	skp_object_s64 blocks;
	skp_object_s64 blksize;
	skp_subject_u32 atime_nsec;
	skp_subject_u32 mtime_nsec;
	skp_subject_u32 ctime_nsec;
	skp_subject_u32 reserved;
};

enum skp_object_query_mode {
	SKP_OBJECT_UPSTREAM = 0,
	SKP_OBJECT_LEGACY_SUBJECT = 1,
	SKP_OBJECT_GROUPED = 2
};

/* Copied before releasing RCU. No rule pointer escapes the query. */
struct skp_kstat_query_result {
	skp_subject_u32 matched;
	skp_subject_u32 legacy_allowed;
	struct skp_kstat_values values;
};
struct skp_map_query_result {
	skp_subject_u32 hidden;
	skp_subject_u32 legacy_allowed;
};

#endif
