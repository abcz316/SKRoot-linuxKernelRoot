// SPDX-License-Identifier: GPL-2.0-only
/* Pure policy contract tests. No syscalls, task impersonation or interception.
 * Build: cc -std=c11 -Wall -Wextra -Werror -pedantic -O2
 *   kernel/skp_subject_policy.c tools/tests/subject_policy_test.c -o /tmp/test
 */
#include "../../kernel/skp_subject_policy.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct skp_subject_policy) == 9400, "fixed policy layout");
_Static_assert(offsetof(struct skp_subject_policy, facts_generation) == 32,
	       "generation layout");
_Static_assert(offsetof(struct skp_subject_policy, profiles) == 56,
	       "profile layout");
_Static_assert(offsetof(struct skp_subject_policy, bindings) == 5304,
	       "binding layout");
_Static_assert(sizeof(struct skp_subject_context) == 32, "internal context layout");
_Static_assert(sizeof(struct skp_subject_decision) == 24, "fixed decision layout");

static unsigned int checks;

static void expect(int condition, const char *name)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL: %s (check %u)\n", name, checks);
		exit(1);
	}
}

static struct skp_subject_policy empty_policy(void)
{
	struct skp_subject_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.version = SKP_SUBJECT_POLICY_VERSION;
	policy.profile_count = 1;
	policy.facts_generation = 0x100000003ULL;
	return policy;
}

static struct skp_subject_context caller(skp_subject_u32 uid)
{
	struct skp_subject_context context;

	memset(&context, 0, sizeof(context));
	context.actual_uid = uid;
	return context;
}

static struct skp_subject_policy matrix_policy(void)
{
	struct skp_subject_policy policy = empty_policy();
	const skp_subject_u32 white[] = { 1001, 10201, 10301 };
	const skp_subject_u32 black[] = { 0, 1000, 10100, 10301 };
	const skp_subject_u32 system[] = { 1000, 10100 };
	const struct skp_subject_binding bindings[] = {
		{ 1000, 7 }, { 10100, 7 }, { 10200, 19 },
		{ 10201, 7 }, { 10301, 19 }
	};

	policy.profile_count = 3;
	policy.profiles[1] = 7;
	policy.profiles[2] = 19;
	policy.whitelist_count = sizeof(white) / sizeof(white[0]);
	policy.blacklist_count = sizeof(black) / sizeof(black[0]);
	policy.system_app_count = sizeof(system) / sizeof(system[0]);
	policy.binding_count = sizeof(bindings) / sizeof(bindings[0]);
	memcpy(policy.whitelist, white, sizeof(white));
	memcpy(policy.blacklist, black, sizeof(black));
	memcpy(policy.system_apps, system, sizeof(system));
	memcpy(policy.bindings, bindings, sizeof(bindings));
	return policy;
}

/* These are hand-specified product expectations, not a second binary-search
 * implementation. Bit N says whether whitelist mode participates with flags N.
 * Worker rows prove category tests use actual credentials while list, system
 * App and profile tests use the verified origin. Full UID rows prohibit modulo
 * normalization and isolated-host inference. */
static void test_identity_matrix(void)
{
	static const struct {
		const char *name;
		skp_subject_u32 actual_uid, origin_uid, verified;
		unsigned int whitelist_bits, blacklisted;
		skp_subject_u32 expected_profile;
	} cases[] = {
		{ "root", 0, 0, 0, 0x55, 1, 0 },
		{ "shared system package", 1000, 0, 0, 0x03, 1, 7 },
		{ "shell", 2000, 0, 0, 0x33, 0, 0 },
		{ "system App", 10100, 0, 0, 0x0f, 1, 7 },
		{ "ordinary grouped App", 10200, 0, 0, 0xff, 0, 19 },
		{ "whitelisted App", 10201, 0, 0, 0x00, 0, 7 },
		{ "both lists", 10301, 0, 0, 0x00, 1, 19 },
		{ "other Android user", 110100, 0, 0, 0xff, 0, 0 },
		{ "unmapped isolated UID", 99001, 0, 0, 0xff, 0, 0 },
		{ "root worker of system App", 0, 10100, 1, 0x05, 1, 7 },
		{ "system worker of system App", 2000, 10100, 1, 0x03, 1, 7 },
		{ "root worker of whitelisted App", 0, 10301, 1, 0x00, 1, 19 },
		{ "App worker of ordinary App", 10555, 10200, 1, 0xff, 0, 19 },
		{ "unverified origin ignored", 10200, 10301, 0, 0xff, 0, 19 },
		{ "root worker of shared system UID", 0, 1000, 1, 0x05, 1, 7 },
		{ "App worker of shared system UID", 10555, 1000, 1, 0x0f, 1, 7 },
		{ "whitelisted system process", 1001, 0, 0, 0x00, 0, 0 }
	};
	struct skp_subject_policy policy = matrix_policy();
	unsigned int mode, flags, i;

	expect(skp_subject_policy_validate(&policy) == 0, "matrix snapshot valid");
	for (mode = 0; mode != 2; ++mode) {
		for (flags = 0; flags != 8; ++flags) {
			policy.mode = mode;
			policy.flags = flags;
			for (i = 0; i != sizeof(cases) / sizeof(cases[0]); ++i) {
				struct skp_subject_context context = caller(cases[i].actual_uid);
				struct skp_subject_decision result;
				unsigned int participates = mode ? cases[i].blacklisted :
					(cases[i].whitelist_bits >> flags) & 1U;

				context.origin_uid = cases[i].origin_uid;
				context.worker_verified = cases[i].verified;
				context.origin_facts_generation = policy.facts_generation;
				result = skp_subject_evaluate(&policy, &context);
				expect(result.applies == participates, cases[i].name);
				expect(result.profile_id == (participates ? cases[i].expected_profile :
					SKP_SUBJECT_NO_PROFILE), "profile selection matrix");
				expect(result.facts_generation == 0x100000003ULL,
				       "full 64-bit generation retained");
				expect(result.effective_uid == (cases[i].verified ?
					cases[i].origin_uid : cases[i].actual_uid), "effective UID matrix");
				context.precise_manager = 1;
				context.origin_facts_generation = 0; /* Even a stale worker is exempt. */
				result = skp_subject_evaluate(&policy, &context);
				expect(!result.applies && result.profile_id == SKP_SUBJECT_NO_PROFILE &&
				       result.reason == SKP_SUBJECT_REASON_MANAGER, "exact manager priority");
			}
		}
	}
}

static void test_validation(void)
{
	struct skp_subject_policy policy = empty_policy();
	struct skp_subject_policy base = matrix_policy();
	unsigned int which, index;

	expect(skp_subject_policy_validate(NULL) == SKP_SUBJECT_ERR_ARGUMENT, "null policy");
	expect(skp_subject_policy_validate(&policy) == 0, "empty default profile valid");
	policy.version++;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_VERSION, "version rejected");
	policy = empty_policy();
	policy.mode = 2;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_HEADER, "unknown mode");
	policy = empty_policy();
	policy.flags = 8;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_HEADER, "unknown flags");
	policy = empty_policy();
	policy.facts_generation = 0;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_HEADER, "incomplete facts");
	for (index = 0; index != 4; ++index) {
		policy = empty_policy();
		policy.reserved[index] = 1;
		expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_HEADER, "reserved header");
	}
	for (which = 0; which != 5; ++which) {
		policy = empty_policy();
		switch (which) {
		case 0: policy.profile_count = SKP_SUBJECT_MAX_PROFILES + 1; break;
		case 1: policy.whitelist_count = SKP_SUBJECT_MAX_LIST_UIDS + 1; break;
		case 2: policy.blacklist_count = SKP_SUBJECT_MAX_LIST_UIDS + 1; break;
		case 3: policy.system_app_count = SKP_SUBJECT_MAX_SYSTEM_UIDS + 1; break;
		default: policy.binding_count = SKP_SUBJECT_MAX_BINDINGS + 1; break;
		}
		expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_COUNT, "capacity overflow");
	}
	policy = empty_policy();
	policy.profile_count = 0;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_COUNT, "missing default count");
	policy = empty_policy();
	policy.profiles[0] = 9;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_PROFILE, "default must be zero");
	policy = base;
	policy.profiles[2] = 7;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_PROFILE, "duplicate profile");
	policy = base;
	policy.profiles[2] = 1;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_PROFILE, "unsorted profiles");
	policy = base;
	policy.profiles[2] = SKP_SUBJECT_NO_PROFILE;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_PROFILE, "sentinel profile");
	for (which = 0; which != 3; ++which) {
		skp_subject_u32 *array;
		skp_subject_u32 count, capacity;

		for (index = 0; index != 5; ++index) {
			policy = base;
			if (which == 0) {
				array = policy.whitelist;
				count = policy.whitelist_count;
				capacity = SKP_SUBJECT_MAX_LIST_UIDS;
			} else if (which == 1) {
				array = policy.blacklist;
				count = policy.blacklist_count;
				capacity = SKP_SUBJECT_MAX_LIST_UIDS;
			} else {
				array = policy.system_apps;
				count = policy.system_app_count;
				capacity = SKP_SUBJECT_MAX_SYSTEM_UIDS;
			}
			switch (index) {
			case 0: array[0] = SKP_SUBJECT_INVALID_UID; break;
			case 1: array[0] = 110100; break;
			case 2: array[1] = array[0]; break;
			case 3: array[1] = array[0] ? array[0] - 1 : 0; break;
			default: array[capacity - 1] = 1; break;
			}
			(void)count;
			expect(skp_subject_policy_validate(&policy) ==
			       (index < 2 ? SKP_SUBJECT_ERR_UID : index < 4 ?
				SKP_SUBJECT_ERR_ORDER : SKP_SUBJECT_ERR_TAIL), "UID list malformed");
		}
	}
	policy = base;
	policy.bindings[1].uid = policy.bindings[0].uid;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_ORDER, "same-profile duplicate UID");
	policy.bindings[1].profile_id = 19;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_BINDING_CONFLICT,
	       "shared UID conflicting complete profiles rejected");
	policy = base;
	policy.bindings[1].uid = 999;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_ORDER, "unsorted binding");
	policy = base;
	policy.bindings[4].uid = 110100;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_UID, "other user binding rejected");
	policy = base;
	policy.bindings[4].profile_id = 20;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_PROFILE, "undeclared complete profile");
	policy = base;
	policy.profiles[SKP_SUBJECT_MAX_PROFILES - 1] = 1;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_TAIL, "profile tail");
	policy = base;
	policy.bindings[SKP_SUBJECT_MAX_BINDINGS - 1].uid = 1;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_TAIL, "binding UID tail");
	policy = base;
	policy.bindings[SKP_SUBJECT_MAX_BINDINGS - 1].profile_id = 1;
	expect(skp_subject_policy_validate(&policy) == SKP_SUBJECT_ERR_TAIL, "binding profile tail");
}

static void test_boundaries(void)
{
	struct skp_subject_policy policy = empty_policy();
	struct skp_subject_context context;
	struct skp_subject_decision result;
	unsigned int i;

	policy.profile_count = SKP_SUBJECT_MAX_PROFILES;
	for (i = 1; i < SKP_SUBJECT_MAX_PROFILES; ++i)
		policy.profiles[i] = i * 7;
	policy.whitelist_count = SKP_SUBJECT_MAX_LIST_UIDS;
	policy.blacklist_count = SKP_SUBJECT_MAX_LIST_UIDS;
	for (i = 0; i < SKP_SUBJECT_MAX_LIST_UIDS; ++i) {
		policy.whitelist[i] = i;
		policy.blacklist[i] = i;
	}
	policy.system_app_count = SKP_SUBJECT_MAX_SYSTEM_UIDS;
	for (i = 0; i < SKP_SUBJECT_MAX_SYSTEM_UIDS; ++i)
		policy.system_apps[i] = i;
	policy.binding_count = SKP_SUBJECT_MAX_BINDINGS;
	for (i = 0; i < SKP_SUBJECT_MAX_BINDINGS; ++i) {
		policy.bindings[i].uid = 10000 + i;
		policy.bindings[i].profile_id = ((i % 31) + 1) * 7;
	}
	expect(skp_subject_policy_validate(&policy) == 0, "all maximum capacities");
	for (i = 0; i < SKP_SUBJECT_MAX_BINDINGS; ++i) {
		context = caller(10000 + i);
		result = skp_subject_evaluate(&policy, &context);
		expect(result.applies && result.profile_id == ((i % 31) + 1) * 7,
		       "every binding at maximum capacity");
	}
	context = caller(10000 + SKP_SUBJECT_MAX_BINDINGS);
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 0, "past final binding defaults");
	context = caller(9999);
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 0, "before first binding defaults");
	policy = empty_policy();
	policy.profile_count = 2;
	policy.profiles[1] = 0xfffffff0U;
	policy.binding_count = 2;
	policy.bindings[0].uid = 0;
	policy.bindings[0].profile_id = 0;
	policy.bindings[1].uid = 99999;
	policy.bindings[1].profile_id = 0xfffffff0U;
	expect(skp_subject_policy_validate(&policy) == 0, "whole user0 UID and stable profile ID boundaries");
	context = caller(0);
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 0, "explicit zero UID/profile is not sentinel");
	context = caller(99999);
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 0xfffffff0U, "high stable profile ID");
	context = caller(100000);
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 0, "user1 system UID not folded to user0 root");
}

static void test_context_and_rebuild(void)
{
	struct skp_subject_policy old = matrix_policy();
	struct skp_subject_policy fresh = empty_policy();
	struct skp_subject_context context = caller(10100);
	struct skp_subject_decision result;
	unsigned int i;

	result = skp_subject_evaluate(&old, &context);
	expect(result.applies && result.profile_id == 7, "old package group active");
	/* Package removal and UID reuse are facts, never incremental list edits.
 * The new package at the same UID has no inherited group or system status. */
	fresh.facts_generation = old.facts_generation + 1;
	fresh.flags = SKP_SUBJECT_EXEMPT_SYSTEM_APPS;
	expect(skp_subject_policy_validate(&fresh) == 0, "rebuilt facts valid");
	result = skp_subject_evaluate(&fresh, &context);
	expect(result.applies && result.profile_id == 0, "reused UID inherits no old group/system fact");
	context = caller(0);
	context.worker_verified = 1;
	context.origin_uid = 10100;
	context.origin_facts_generation = old.facts_generation;
	result = skp_subject_evaluate(&old, &context);
	expect(result.applies && result.profile_id == 7, "matching verified worker generation");
	result = skp_subject_evaluate(&fresh, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_STALE_WORKER &&
	       result.profile_id == SKP_SUBJECT_NO_PROFILE, "stale worker cannot follow UID reuse");
	context.origin_facts_generation = fresh.facts_generation;
	result = skp_subject_evaluate(&fresh, &context);
	expect(result.applies && result.profile_id == 0, "freshly verified origin uses new facts only");
	context.worker_verified = 0;
	context.origin_uid = SKP_SUBJECT_INVALID_UID;
	context.origin_facts_generation = 0;
	result = skp_subject_evaluate(&fresh, &context);
	expect(result.applies && result.effective_uid == 0, "unverified fields ignored completely");
	for (i = 0; i != 5; ++i) {
		context = caller(10200);
		switch (i) {
		case 0: context.actual_uid = SKP_SUBJECT_INVALID_UID; break;
		case 1: context.worker_verified = 2; break;
		case 2: context.precise_manager = 2; break;
		case 3:
			context.worker_verified = 1;
			context.origin_uid = SKP_SUBJECT_INVALID_UID;
			context.origin_facts_generation = old.facts_generation;
			break;
		default:
			context.worker_verified = 1;
			context.origin_uid = 110200;
			context.origin_facts_generation = old.facts_generation;
			break;
		}
		result = skp_subject_evaluate(&old, &context);
		expect(!result.applies && result.profile_id == SKP_SUBJECT_NO_PROFILE &&
		       result.reason == SKP_SUBJECT_REASON_INVALID, "malformed context suppressed");
	}
	context = caller(10200);
	result = skp_subject_evaluate(NULL, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_INVALID, "null evaluate policy");
	result = skp_subject_evaluate(&old, NULL);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_INVALID, "null evaluate context");
	old.binding_count = 0xffffffffU;
	result = skp_subject_evaluate(&old, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_INVALID,
	       "untrusted header bounds checked before lookup");
}

static void test_root_accounting_identity(void)
{
	struct skp_subject_policy policy = matrix_policy();
	struct skp_subject_context context = caller(0);
	struct skp_subject_decision result;
	policy.mode = SKP_SUBJECT_BLACKLIST;
	policy.flags = SKP_SUBJECT_EXEMPT_ALL;
	context.accounting_uid = 10301;
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.profile_id == 19 && result.effective_uid == 10301,
	       "specified root app keeps accounting identity despite broad flags");
	context.accounting_uid = 10200;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_NOT_BLACKLISTED,
	       "another root app does not inherit selected rules");
	context.accounting_uid = 0;
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.effective_uid == 0 && result.profile_id == 0,
	       "unattributed root preserves explicit UID zero selection");
	context.accounting_uid = 110301;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.effective_uid == 110301,"no Android-user UID folding");
	context.accounting_uid = SKP_SUBJECT_INVALID_UID;
	result = skp_subject_evaluate(&policy, &context);
	expect(result.applies && result.effective_uid == 0,"invalid account does not substitute identity");
	context.actual_uid = 10200;context.accounting_uid = 10301;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.effective_uid == 10200,"ordinary callers retain actual UID");
	context.actual_uid = 0;context.accounting_uid = 10301;context.precise_manager = 1;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_MANAGER,"exact manager remains exempt");
	context.precise_manager = 0;policy.mode = SKP_SUBJECT_WHITELIST;
	policy.flags = SKP_SUBJECT_EXEMPT_ROOT;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_ROOT,"root exclusion still tests actual UID");
	policy.flags = 0;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_WHITELIST,"excluded root package uses account");
	context.accounting_uid = 10100;policy.flags = SKP_SUBJECT_EXEMPT_SYSTEM_APPS;
	result = skp_subject_evaluate(&policy, &context);
	expect(!result.applies && result.reason == SKP_SUBJECT_REASON_SYSTEM_APP,"system package classification retained");
}

int main(void)
{
	test_identity_matrix();
	test_validation();
	test_boundaries();
	test_context_and_rebuild();
	test_root_accounting_identity();
	printf("SKP_SUBJECT_POLICY checks=%u passed=true kernel_calls=false\n", checks);
	return 0;
}
