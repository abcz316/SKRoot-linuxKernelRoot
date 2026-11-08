/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_SEQUENTIAL_H
#define SUSFS_SKP_SEQUENTIAL_H

#include "skp_group_objects.h"

#define SKP_SEQUENTIAL_NODE "/proc/susfs_skp_policy"
#define SKP_SEQUENTIAL_MAGIC 0x53514b50U
#define SKP_SEQUENTIAL_VERSION 1U

enum skp_sequential_command {
	SKP_SEQ_CLEAR_FAMILY = 1,
	SKP_SEQ_ADD_RULE = 2,
	SKP_SEQ_REGISTER_MANAGER = 3,
	/* Same message layout, explicit opt-in: source-authorized read-only content.
	 * Older kernels reject this command instead of treating it as a path swap. */
	SKP_SEQ_ADD_CONTENT = 4,
	/* PATH subtype: rule.path is an exact file/directory basename, not a path.
	 * Separate command keeps older kernels from interpreting it as a path. */
	SKP_SEQ_ADD_DIR_NAME = 5,
	/* PATH subtype: keep the directory itself visible; hide its descendants. */
	SKP_SEQ_ADD_PATH_CONTENTS = 6,
};
enum skp_sequential_family {
	SKP_SEQ_PATH = 1,
	SKP_SEQ_KSTAT = 2,
	SKP_SEQ_MAP = 3,
	SKP_SEQ_REDIRECT = 4,
	SKP_SEQ_MOUNT = 5,
	SKP_SEQ_FAMILY_COUNT = 5,
};
#define SKP_SEQ_ALLOW_PENDING 1U

/* Native little-endian AArch64, with no pointers or transaction metadata.
 * CLEAR is exactly a header. REGISTER_MANAGER is exactly a header with family
 * zero; its exemption is bound to this fd's opener, never its descendants.
 * ADD is exactly skp_sequential_message. Each write returns count or -errno.
 * Its selector is immutable and self-contained; profile_id selects the group.
 * A path override is encoded as a selector with profile 0, not another table.
 * ALLOW_PENDING retains a missing PATH rule for the upstream retry cadence.
 */
struct skp_sequential_header {
	skp_subject_u32 magic;
	skp_subject_u32 version;
	skp_subject_u32 size;
	skp_subject_u32 command;
	skp_subject_u32 family;
	skp_subject_u32 flags;
};
struct skp_sequential_rule {
	skp_subject_u32 profile_id;
	skp_subject_u32 reserved;
	struct skp_subject_policy subjects;
	char path[SKP_GROUP_PATH_LEN];
	char target[SKP_GROUP_PATH_LEN];
	struct skp_kstat_values values;
};
struct skp_sequential_message {
	struct skp_sequential_header header;
	struct skp_sequential_rule rule;
};
SKP_STATIC_ASSERT(sizeof(struct skp_sequential_header) == 24, "sequential header ABI");
SKP_STATIC_ASSERT(sizeof(struct skp_sequential_rule) == 10008, "sequential rule ABI");
SKP_STATIC_ASSERT(sizeof(struct skp_sequential_message) == 10032, "sequential message ABI");

#endif
