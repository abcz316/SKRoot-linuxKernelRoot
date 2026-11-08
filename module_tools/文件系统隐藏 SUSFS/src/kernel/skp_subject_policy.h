/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_SKP_SUBJECT_POLICY_H
#define SUSFS_SKP_SUBJECT_POLICY_H

/* Self-contained subject selector shared by per-rule kernel and host code.
 * Each rule owns a stable selector reference. No filesystem lookup, package
 * service, transaction version or identity guessing belongs on this path. */
#ifdef __cplusplus
#define SKP_STATIC_ASSERT static_assert
#else
#define SKP_STATIC_ASSERT _Static_assert
#endif

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 skp_subject_u32;
typedef u64 skp_subject_u64;
#elif defined(SKP_SUBJECT_FREESTANDING)
/* Existing raw-syscall tools are built without a libc sysroot. Keep this
 * branch explicit instead of changing the normal host or kernel includes. */
typedef unsigned int skp_subject_u32;
typedef unsigned long long skp_subject_u64;
SKP_STATIC_ASSERT(sizeof(skp_subject_u32) == 4, "32-bit subject field");
SKP_STATIC_ASSERT(sizeof(skp_subject_u64) == 8, "64-bit subject field");
#else
#include <stdint.h>
typedef uint32_t skp_subject_u32;
typedef uint64_t skp_subject_u64;
#endif

#define SKP_SUBJECT_POLICY_VERSION 1U
#define SKP_SUBJECT_MAX_LIST_UIDS 128U
#define SKP_SUBJECT_MAX_SYSTEM_UIDS 1024U
#define SKP_SUBJECT_MAX_BINDINGS 512U
#define SKP_SUBJECT_MAX_PROFILES 32U
#define SKP_SUBJECT_INVALID_UID ((skp_subject_u32)0xffffffffU)
#define SKP_SUBJECT_NO_PROFILE ((skp_subject_u32)0xffffffffU)
#define SKP_SUBJECT_USER0_UID_LIMIT 100000U

enum skp_subject_mode {
	SKP_SUBJECT_WHITELIST = 0,
	SKP_SUBJECT_BLACKLIST = 1
};

enum skp_subject_flags {
	SKP_SUBJECT_EXEMPT_ROOT = 1U << 0,
	SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES = 1U << 1,
	SKP_SUBJECT_EXEMPT_SYSTEM_APPS = 1U << 2,
	SKP_SUBJECT_EXEMPT_ALL = (1U << 3) - 1U
};

struct skp_subject_binding {
	skp_subject_u32 uid;
	skp_subject_u32 profile_id;
};

/* UID facts are resolved by the PLUS package inventory. A UID
 * is stored whole: never modulo 100000, never infer an isolated UID's owner.
 * System packages may legitimately share UID 1000 (or another system UID).
 * Shared-UID package members are collapsed by the inventory resolver; if they
 * request different profiles, validation rejects the conflicting binding.
 * Every array is strictly increasing, and every unused slot must be zero. */
struct skp_subject_policy {
	skp_subject_u32 version;
	skp_subject_u32 mode;
	skp_subject_u32 flags;
	skp_subject_u32 profile_count;
	skp_subject_u32 whitelist_count;
	skp_subject_u32 blacklist_count;
	skp_subject_u32 system_app_count;
	skp_subject_u32 binding_count;
	skp_subject_u64 facts_generation;
	skp_subject_u32 reserved[4];
	skp_subject_u32 profiles[SKP_SUBJECT_MAX_PROFILES];
	skp_subject_u32 whitelist[SKP_SUBJECT_MAX_LIST_UIDS];
	skp_subject_u32 blacklist[SKP_SUBJECT_MAX_LIST_UIDS];
	skp_subject_u32 system_apps[SKP_SUBJECT_MAX_SYSTEM_UIDS];
	struct skp_subject_binding bindings[SKP_SUBJECT_MAX_BINDINGS];
};

/* Only trusted kernel integration may assert either identity flag. A manager
 * is an exact live task/group identity, never "any root" or a descendant by
 * inheritance. A verified worker carries a held, start-time checked live task
 * and an explicitly verified package origin from this facts generation. The
 * core does not perform registration or prove those assertions itself.
 * Unverified/stale origin fields are never used as a substitute UID. */
struct skp_subject_context {
	skp_subject_u32 actual_uid;
	skp_subject_u32 origin_uid;
	skp_subject_u32 worker_verified;
	skp_subject_u32 precise_manager;
	skp_subject_u64 origin_facts_generation;
	/* Trusted kernel credential user-accounting UID. SKP root changes access
	 * UIDs while retaining this account. Only actual UID 0 uses it for package
	 * matching; never a PID/comm/parent guess or user-provided identity. */
	skp_subject_u32 accounting_uid;
};

enum skp_subject_error {
	SKP_SUBJECT_VALID = 0,
	SKP_SUBJECT_ERR_ARGUMENT = -1,
	SKP_SUBJECT_ERR_VERSION = -2,
	SKP_SUBJECT_ERR_HEADER = -3,
	SKP_SUBJECT_ERR_COUNT = -4,
	SKP_SUBJECT_ERR_PROFILE = -5,
	SKP_SUBJECT_ERR_UID = -6,
	SKP_SUBJECT_ERR_ORDER = -7,
	SKP_SUBJECT_ERR_TAIL = -8,
	SKP_SUBJECT_ERR_BINDING_CONFLICT = -9
};

enum skp_subject_reason {
	SKP_SUBJECT_REASON_INVALID = 0,
	SKP_SUBJECT_REASON_MANAGER = 1,
	SKP_SUBJECT_REASON_ROOT = 2,
	SKP_SUBJECT_REASON_SYSTEM_PROCESS = 3,
	SKP_SUBJECT_REASON_SYSTEM_APP = 4,
	SKP_SUBJECT_REASON_WHITELIST = 5,
	SKP_SUBJECT_REASON_NOT_BLACKLISTED = 6,
	SKP_SUBJECT_REASON_DEFAULT_PROFILE = 7,
	SKP_SUBJECT_REASON_GROUP_PROFILE = 8,
	SKP_SUBJECT_REASON_STALE_WORKER = 9
};

struct skp_subject_decision {
	skp_subject_u32 applies;
	skp_subject_u32 profile_id;
	skp_subject_u32 reason;
	skp_subject_u32 effective_uid;
	skp_subject_u64 facts_generation;
};

/* Full input validation. No mutation, normalization or allocation.
 * Duplicate UIDs, including same-profile duplicates, are rejected; conflicting
 * shared-UID assignments have their own error. Profile 0 must always exist. */
int skp_subject_policy_validate(const struct skp_subject_policy *policy);

/* Read under the rule selector lifetime guard. Requires a successfully
 * validated immutable policy; the bounded header is checked defensively, but
 * full arrays are deliberately not rescanned in a filesystem hook. Invalid
 * context or stale verified worker suppresses interception. Exemptions are
 * evaluated before profile selection. Blacklist mode ignores the three broad
 * exemption flags, but never overrides the exact manager exemption. */
struct skp_subject_decision
skp_subject_evaluate(const struct skp_subject_policy *policy,
		     const struct skp_subject_context *context);

#endif /* SUSFS_SKP_SUBJECT_POLICY_H */
