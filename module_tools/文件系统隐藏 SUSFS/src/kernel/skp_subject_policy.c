// SPDX-License-Identifier: GPL-2.0-only
#include "skp_subject_policy.h"

static int skp_subject_header_valid(const struct skp_subject_policy *policy)
{
	skp_subject_u32 i;

	if (!policy)
		return SKP_SUBJECT_ERR_ARGUMENT;
	if (policy->version != SKP_SUBJECT_POLICY_VERSION)
		return SKP_SUBJECT_ERR_VERSION;
	if (policy->mode > SKP_SUBJECT_BLACKLIST ||
	    (policy->flags & ~SKP_SUBJECT_EXEMPT_ALL) ||
	    !policy->facts_generation)
		return SKP_SUBJECT_ERR_HEADER;
	for (i = 0; i < 4; ++i)
		if (policy->reserved[i])
			return SKP_SUBJECT_ERR_HEADER;
	if (!policy->profile_count ||
	    policy->profile_count > SKP_SUBJECT_MAX_PROFILES ||
	    policy->whitelist_count > SKP_SUBJECT_MAX_LIST_UIDS ||
	    policy->blacklist_count > SKP_SUBJECT_MAX_LIST_UIDS ||
	    policy->system_app_count > SKP_SUBJECT_MAX_SYSTEM_UIDS ||
	    policy->binding_count > SKP_SUBJECT_MAX_BINDINGS)
		return SKP_SUBJECT_ERR_COUNT;
	return SKP_SUBJECT_VALID;
}

/* All lookup sizes come from a bounded header, including on invalid input. */
static int skp_subject_contains(const skp_subject_u32 *uids,
				skp_subject_u32 count, skp_subject_u32 uid)
{
	skp_subject_u32 low = 0, high = count;

	while (low < high) {
		skp_subject_u32 middle = low + (high - low) / 2;

		if (uids[middle] == uid)
			return 1;
		if (uids[middle] < uid)
			low = middle + 1;
		else
			high = middle;
	}
	return 0;
}

static int skp_subject_uid_array_valid(const skp_subject_u32 *uids,
				     skp_subject_u32 count,
				     skp_subject_u32 capacity)
{
	skp_subject_u32 i;

	for (i = 0; i < count; ++i) {
		if (uids[i] >= SKP_SUBJECT_USER0_UID_LIMIT)
			return SKP_SUBJECT_ERR_UID;
		if (i && uids[i] <= uids[i - 1])
			return SKP_SUBJECT_ERR_ORDER;
	}
	for (; i < capacity; ++i)
		if (uids[i])
			return SKP_SUBJECT_ERR_TAIL;
	return SKP_SUBJECT_VALID;
}

int skp_subject_policy_validate(const struct skp_subject_policy *policy)
{
	skp_subject_u32 i;
	int error = skp_subject_header_valid(policy);

	if (error)
		return error;
	if (policy->profiles[0] != 0)
		return SKP_SUBJECT_ERR_PROFILE;
	for (i = 0; i < policy->profile_count; ++i) {
		if (policy->profiles[i] == SKP_SUBJECT_NO_PROFILE ||
		    (i && policy->profiles[i] <= policy->profiles[i - 1]))
			return SKP_SUBJECT_ERR_PROFILE;
	}
	for (; i < SKP_SUBJECT_MAX_PROFILES; ++i)
		if (policy->profiles[i])
			return SKP_SUBJECT_ERR_TAIL;
	error = skp_subject_uid_array_valid(policy->whitelist,
		policy->whitelist_count, SKP_SUBJECT_MAX_LIST_UIDS);
	if (error)
		return error;
	error = skp_subject_uid_array_valid(policy->blacklist,
		policy->blacklist_count, SKP_SUBJECT_MAX_LIST_UIDS);
	if (error)
		return error;
	error = skp_subject_uid_array_valid(policy->system_apps,
		policy->system_app_count, SKP_SUBJECT_MAX_SYSTEM_UIDS);
	if (error)
		return error;
	for (i = 0; i < policy->binding_count; ++i) {
		const struct skp_subject_binding *binding = &policy->bindings[i];

		if (binding->uid >= SKP_SUBJECT_USER0_UID_LIMIT)
			return SKP_SUBJECT_ERR_UID;
		if (i && binding->uid == policy->bindings[i - 1].uid)
			return binding->profile_id !=
				policy->bindings[i - 1].profile_id ?
				SKP_SUBJECT_ERR_BINDING_CONFLICT :
				SKP_SUBJECT_ERR_ORDER;
		if (i && binding->uid < policy->bindings[i - 1].uid)
			return SKP_SUBJECT_ERR_ORDER;
		if (!skp_subject_contains(policy->profiles, policy->profile_count,
					  binding->profile_id))
			return SKP_SUBJECT_ERR_PROFILE;
	}
	for (; i < SKP_SUBJECT_MAX_BINDINGS; ++i)
		if (policy->bindings[i].uid || policy->bindings[i].profile_id)
			return SKP_SUBJECT_ERR_TAIL;
	return SKP_SUBJECT_VALID;
}

static int skp_subject_find_binding(const struct skp_subject_policy *policy,
				  skp_subject_u32 uid,
				  skp_subject_u32 *profile_id)
{
	skp_subject_u32 low = 0, high = policy->binding_count;

	while (low < high) {
		skp_subject_u32 middle = low + (high - low) / 2;
		const struct skp_subject_binding *binding = &policy->bindings[middle];

		if (binding->uid == uid) {
			*profile_id = binding->profile_id;
			return 1;
		}
		if (binding->uid < uid)
			low = middle + 1;
		else
			high = middle;
	}
	return 0;
}

struct skp_subject_decision
skp_subject_evaluate(const struct skp_subject_policy *policy,
		     const struct skp_subject_context *context)
{
	struct skp_subject_decision result = {
		0, SKP_SUBJECT_NO_PROFILE, SKP_SUBJECT_REASON_INVALID,
		SKP_SUBJECT_INVALID_UID, 0
	};
	skp_subject_u32 profile_id = 0;
	int grouped;

	if (skp_subject_header_valid(policy) || !context)
		return result;
	result.facts_generation = policy->facts_generation;
	result.effective_uid = context->actual_uid;
	if (policy->profiles[0] != 0 ||
	    context->actual_uid == SKP_SUBJECT_INVALID_UID ||
	    context->worker_verified > 1 || context->precise_manager > 1)
		return result;
	if (context->precise_manager) {
		result.reason = SKP_SUBJECT_REASON_MANAGER;
		return result;
	}
	/* Broad privilege exclusions still use actual_uid below. Only package
	 * identity follows the credential's retained user-accounting account. */
	if (context->actual_uid == 0 && context->accounting_uid &&
	    context->accounting_uid != SKP_SUBJECT_INVALID_UID)
		result.effective_uid = context->accounting_uid;
	if (context->worker_verified) {
		if (context->origin_facts_generation != policy->facts_generation) {
			result.reason = SKP_SUBJECT_REASON_STALE_WORKER;
			return result;
		}
		if (context->origin_uid >= SKP_SUBJECT_USER0_UID_LIMIT)
			return result;
		result.effective_uid = context->origin_uid;
	}
	if (policy->mode == SKP_SUBJECT_BLACKLIST) {
		if (!skp_subject_contains(policy->blacklist,
				policy->blacklist_count, result.effective_uid)) {
			result.reason = SKP_SUBJECT_REASON_NOT_BLACKLISTED;
			return result;
		}
	} else {
		if ((policy->flags & SKP_SUBJECT_EXEMPT_ROOT) &&
		    context->actual_uid == 0) {
			result.reason = SKP_SUBJECT_REASON_ROOT;
			return result;
		}
		if ((policy->flags & SKP_SUBJECT_EXEMPT_SYSTEM_PROCESSES) &&
		    context->actual_uid > 0 && context->actual_uid < 10000) {
			result.reason = SKP_SUBJECT_REASON_SYSTEM_PROCESS;
			return result;
		}
		if ((policy->flags & SKP_SUBJECT_EXEMPT_SYSTEM_APPS) &&
		    skp_subject_contains(policy->system_apps,
				policy->system_app_count, result.effective_uid)) {
			result.reason = SKP_SUBJECT_REASON_SYSTEM_APP;
			return result;
		}
		if (skp_subject_contains(policy->whitelist,
				policy->whitelist_count, result.effective_uid)) {
			result.reason = SKP_SUBJECT_REASON_WHITELIST;
			return result;
		}
	}
	grouped = skp_subject_find_binding(policy, result.effective_uid, &profile_id);
	if (!skp_subject_contains(policy->profiles, policy->profile_count, profile_id))
		return result;
	result.applies = 1;
	result.profile_id = profile_id;
	result.reason = grouped ? SKP_SUBJECT_REASON_GROUP_PROFILE :
		SKP_SUBJECT_REASON_DEFAULT_PROFILE;
	return result;
}
