// SPDX-License-Identifier: GPL-2.0-only
/* Development-only LKM policy client. No listener, credentials, PID selectors,
 * arbitrary control-node paths, write retries or kernel-loader behavior.
 *
 * aarch64-linux-android26-clang -O2 -nostdlib -static-pie \
 *   -fno-stack-protector -fno-builtin -Wl,-e,_start \
 *   -Wl,-z,max-page-size=16384 \
 *   tools/skp_policyctl.c kernel/skp_subject_policy.c \
 *   kernel/skp_group_paths.c kernel/skp_group_objects.c \
 *   kernel/skp_full_objects.c -o skp_policyctl
 *
 * status
 * apply <raw-9400-byte-facts-snapshot> <expected-generation-decimal>
 * apply-paths <raw-43208-byte-path-snapshot> <expected-generation-decimal>
 * apply-objects <raw-71384-byte-complete-snapshot> <expected-generation-decimal>
 * apply-full <raw-121576-byte-five-family-snapshot> <expected-generation-decimal>
 * --replace-objects / --replace-full alias apply-objects / apply-full.
 * upstream <expected-generation-decimal>
 *
 * A snapshot is trusted inventory data, NOT a package-name resolver. Full
 * policy-core validation precedes opening the fixed node for writing. The
 * legacy apply command remains profile-0-only; grouped paths use a separate
 * frame. Each frame is sent in exactly ONE write syscall. A negative/short
 * write remains UNKNOWN even after read-only reconciliation, never an
 * invitation to replay. Readback checks generation, mode, facts and, for
 * grouped paths, the object-family capability. It does not attest to Hooks
 * or device effects.
 */
#include "../kernel/skp_policy_adapter.h"

typedef __INTPTR_TYPE__ sysarg;
typedef unsigned long usize;
typedef skp_subject_u64 u64;

#define SC_OPENAT 56
#define SC_CLOSE 57
#define SC_LSEEK 62
#define SC_READ 63
#define SC_WRITE 64
#define SC_FSTAT 80
#define AT_CWD (-100)
#define OPEN_RDONLY 0
#define OPEN_RDWR 2
#define OPEN_NONBLOCK 0x800
#define OPEN_NOFOLLOW 0x20000
#define OPEN_CLOEXEC 0x80000
#define STATUS_LIMIT 4096U
#define U64_MAX_VALUE ((u64)~(u64)0)

/* asm-generic stat, native ARM64 syscall ABI; no libc struct stat dependency. */
struct native_stat {
	u64 dev, ino;
	unsigned int mode, nlink, uid, gid;
	u64 rdev, pad1;
	long size;
	int blksize, pad2;
	long blocks, atime;
	u64 atime_nsec;
	long mtime;
	u64 mtime_nsec;
	long ctime;
	u64 ctime_nsec;
	unsigned int unused[2];
};

_Static_assert(sizeof(struct native_stat) == 128, "ARM64 stat ABI");
_Static_assert(sizeof(struct skp_subject_policy) == 9400, "policy ABI changed");
_Static_assert(sizeof(struct skp_policy_message) == 9432, "frame ABI changed");
_Static_assert(sizeof(struct skp_group_paths_config) == 43208, "path config ABI changed");
_Static_assert(sizeof(struct skp_group_paths_message) == 43240, "path frame ABI changed");
_Static_assert(sizeof(struct skp_kstat_values) == 88, "kstat payload ABI changed");
_Static_assert(sizeof(struct skp_group_objects_config) == 71384, "object config ABI changed");
_Static_assert(sizeof(struct skp_group_objects_message) == 71416, "object frame ABI changed");
_Static_assert(sizeof(struct skp_full_objects_config) == 121576, "full config ABI changed");
_Static_assert(sizeof(struct skp_full_objects_message) == 121608, "full frame ABI changed");

#ifdef SKP_POLICYCTL_HOSTTEST
extern sysarg skp_policyctl_syscall(sysarg, sysarg, sysarg, sysarg);
#else
static sysarg skp_policyctl_syscall(sysarg nr, sysarg a, sysarg b, sysarg c)
{
	register sysarg x8 __asm__("x8") = nr;
	register sysarg x0 __asm__("x0") = a;
	register sysarg x1 __asm__("x1") = b;
	register sysarg x2 __asm__("x2") = c;

	__asm__ volatile("svc #0" : "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
	return x0;
}
#endif

static struct skp_policy_message message;
static struct skp_group_paths_message paths_message;
static struct skp_group_objects_message objects_message;
static struct skp_full_objects_message full_message;
static char status_text[STATUS_LIMIT + 1];

static usize text_length(const char *text)
{
	usize n = 0;
	while (text[n])
		n++;
	return n;
}

static int same(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static int emit(const char *text, usize n)
{
	while (n) {
		long written = skp_policyctl_syscall(SC_WRITE, 1, (sysarg)text, n);
		if (written == -4)
			continue;
		if (written <= 0 || (usize)written > n)
			return -1;
		text += written;
		n -= written;
	}
	return 0;
}

static int error(const char *result, const char *reason, long number, int code)
{
	char digits[24];
	unsigned long value = number < 0 ? (unsigned long)-number : (unsigned long)number;
	usize n = 0;
	const char *prefix = "{\"result\":\"";

	(void)emit(prefix, text_length(prefix));
	(void)emit(result, text_length(result));
	(void)emit("\",\"reason\":\"", 12);
	(void)emit(reason, text_length(reason));
	(void)emit("\",\"error\":", 10);
	do {
		digits[n++] = (char)('0' + value % 10);
		value /= 10;
	} while (value);
	while (n)
		(void)emit(&digits[--n], 1);
	(void)emit("}\n", 2);
	return code;
}

/* No sign, whitespace, suffix, hex, empty value, or overflow is accepted. */
static int decimal_span(const char *text, usize n, u64 *value)
{
	u64 v = 0;
	usize i;
	if (!n)
		return -1;
	for (i = 0; i < n; ++i) {
		unsigned int digit = (unsigned char)text[i] - '0';
		if (digit > 9 || v > (U64_MAX_VALUE - digit) / 10)
			return -1;
		v = v * 10 + digit;
	}
	*value = v;
	return 0;
}

static int snapshot_read(const char *path, void *data, usize bytes)
{
	struct native_stat st;
	char *destination = data;
	char extra;
	usize done = 0;
	long fd, rc;
	int result = 0;

	fd = skp_policyctl_syscall(SC_OPENAT, AT_CWD, (sysarg)path,
		OPEN_RDONLY | OPEN_CLOEXEC | OPEN_NOFOLLOW | OPEN_NONBLOCK);
	if (fd < 0)
		return (int)fd;
	rc = skp_policyctl_syscall(SC_FSTAT, fd, (sysarg)&st, 0);
	if (rc < 0) {
		result = (int)rc;
		goto out;
	}
	if ((st.mode & 0170000) != 0100000 || st.size != (long)bytes) {
		result = -90; /* EMSGSIZE; no devices, pipes or directories as input. */
		goto out;
	}
	while (done < bytes) {
		rc = skp_policyctl_syscall(SC_READ, fd, (sysarg)(destination + done),
			bytes - done);
		if (rc == -4)
			continue;
		if (rc <= 0 || (usize)rc > bytes - done) {
			result = rc < 0 ? (int)rc : -90;
			goto out;
		}
		done += rc;
	}
	do {
		rc = skp_policyctl_syscall(SC_READ, fd, (sysarg)&extra, 1);
	} while (rc == -4);
	if (rc)
		result = rc < 0 ? (int)rc : -90;
out:
	(void)skp_policyctl_syscall(SC_CLOSE, fd, 0, 0);
	return result;
}

struct status_fields {
	u64 generation, facts_generation;
	u64 grouped_path_count, active_profile_count, grouped_kstat_count, grouped_map_count;
	u64 grouped_redirect_count, grouped_mount_count;
	unsigned int seen;
	int skp, paths, objects, full, group_paths, group_objects, group_kstat, group_map;
	int group_redirect, group_mount, group_full;
};

#define STATUS_LEGACY_FIELDS 127U
#define STATUS_PATH_FIELDS (128U | 256U | 512U | 1024U | 2048U | 4096U | 8192U)
#define STATUS_OBJECT_FIELDS (STATUS_PATH_FIELDS | 16384U | 32768U | 65536U | 131072U | 262144U | 524288U)
#define STATUS_FULL_FIELDS (STATUS_OBJECT_FIELDS | 1048576U | 2097152U | 4194304U | 8388608U | 16777216U | 33554432U | 67108864U)

struct span { const char *text; usize n; };

static int span_is(struct span s, const char *text)
{
	usize i, n = text_length(text);
	if (s.n != n)
		return 0;
	for (i = 0; i < n; ++i)
		if (s.text[i] != text[i])
			return 0;
	return 1;
}

static void skip_space(const char **cursor)
{
	while (**cursor == ' ' || **cursor == '\n' || **cursor == '\r' || **cursor == '\t')
		(*cursor)++;
}

/* The fixed version-1 node emits a flat object. Reject controls, escapes,
 * nested data, duplicate required fields and partial/non-JSON responses. */
static int json_string(const char **cursor, struct span *span)
{
	const char *start;
	if (*(*cursor)++ != '"')
		return -1;
	start = *cursor;
	while (**cursor && **cursor != '"') {
		if ((unsigned char)**cursor < 0x20 || **cursor == '\\')
			return -1;
		(*cursor)++;
	}
	if (**cursor != '"')
		return -1;
	span->text = start;
	span->n = *cursor - start;
	(*cursor)++;
	return 0;
}

static int status_parse(const char *text, struct status_fields *status)
{
	const char *cursor = text;
	unsigned int seen = 0;
	u64 value;
	status->generation = status->facts_generation = 0;
	status->grouped_path_count = status->active_profile_count = 0;
	status->grouped_kstat_count = status->grouped_map_count = 0;
	status->grouped_redirect_count = status->grouped_mount_count = 0;
	status->seen = 0;
	status->skp = status->paths = status->objects = status->group_paths = 0;
	status->group_objects = status->group_kstat = status->group_map = 0;
	status->full = status->group_redirect = status->group_mount = status->group_full = 0;

	skip_space(&cursor);
	if (*cursor++ != '{')
		return -1;
	for (;;) {
		struct span key, token;
		unsigned int bit = 0;
		int quoted = 0;

		skip_space(&cursor);
		if (json_string(&cursor, &key))
			return -1;
		skip_space(&cursor);
		if (*cursor++ != ':')
			return -1;
		skip_space(&cursor);
		if (*cursor == '"') {
			quoted = 1;
			if (json_string(&cursor, &token))
				return -1;
		} else {
			token.text = cursor;
			while (*cursor && *cursor != ',' && *cursor != '}' &&
			       *cursor != ' ' && *cursor != '\n' && *cursor != '\r' && *cursor != '\t')
				cursor++;
			token.n = cursor - token.text;
			if (!span_is(token, "true") && !span_is(token, "false") &&
			    !span_is(token, "null") && decimal_span(token.text, token.n, &value))
				return -1;
		}
		if (span_is(key, "backend")) {
			bit = 1;
			if (!quoted || !span_is(token, "lkm"))
				return -1;
		} else if (span_is(key, "mode")) {
			bit = 2;
			if (!quoted || (!span_is(token, "skp") && !span_is(token, "upstream")))
				return -1;
			status->skp = span_is(token, "skp");
		} else if (span_is(key, "generation") || span_is(key, "facts_generation")) {
			bit = span_is(key, "generation") ? 4 : 8;
			if (!quoted || decimal_span(token.text, token.n, &value))
				return -1;
			if (bit == 4)
				status->generation = value;
			else
				status->facts_generation = value;
		} else if (span_is(key, "policy_abi") || span_is(key, "message_bytes") ||
			   span_is(key, "policy_bytes")) {
			bit = span_is(key, "policy_abi") ? 16 : span_is(key, "message_bytes") ? 32 : 64;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value != (bit == 16 ? SKP_POLICY_MESSAGE_VERSION :
				      bit == 32 ? sizeof(message) : sizeof(message.policy)))
				return -1;
		} else if (span_is(key, "path_message_bytes") || span_is(key, "path_config_bytes")) {
			bit = span_is(key, "path_message_bytes") ? 128 : 256;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value != (bit == 128 ? sizeof(paths_message) : sizeof(paths_message.config)))
				return -1;
		} else if (span_is(key, "group_path_isolation") || span_is(key, "group_object_isolation")) {
			bit = span_is(key, "group_path_isolation") ? 512 : 1024;
			if (quoted || (!span_is(token, "true") && !span_is(token, "false")))
				return -1;
			if (bit == 512)
				status->group_paths = span_is(token, "true");
			else
				status->group_objects = span_is(token, "true");
		} else if (span_is(key, "grouped_path_count") || span_is(key, "active_profile_count")) {
			bit = span_is(key, "grouped_path_count") ? 2048 : 4096;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value > (bit == 2048 ? SKP_GROUP_PATHS_MAX : SKP_SUBJECT_MAX_PROFILES))
				return -1;
			if (bit == 2048)
				status->grouped_path_count = value;
			else
				status->active_profile_count = value;
		} else if (span_is(key, "object_families")) {
			bit = 8192;
			if (!quoted || (!span_is(token, "path") && !span_is(token, "upstream") &&
				!span_is(token, "path,kstat,map") && !span_is(token, "path,kstat,map,redirect,mount")))
				return -1;
			status->paths = span_is(token, "path");
			status->objects = span_is(token, "path,kstat,map");
			status->full = span_is(token, "path,kstat,map,redirect,mount");
		} else if (span_is(key, "object_message_bytes") || span_is(key, "object_config_bytes")) {
			bit = span_is(key, "object_message_bytes") ? 16384 : 32768;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value != (bit == 16384 ? sizeof(objects_message) : sizeof(objects_message.config)))
				return -1;
		} else if (span_is(key, "group_kstat_isolation") || span_is(key, "group_map_isolation")) {
			bit = span_is(key, "group_kstat_isolation") ? 65536 : 131072;
			if (quoted || (!span_is(token, "true") && !span_is(token, "false")))
				return -1;
			if (bit == 65536)
				status->group_kstat = span_is(token, "true");
			else
				status->group_map = span_is(token, "true");
		} else if (span_is(key, "grouped_kstat_count") || span_is(key, "grouped_map_count")) {
			bit = span_is(key, "grouped_kstat_count") ? 262144 : 524288;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value > (bit == 262144 ? SKP_GROUP_KSTATS_MAX : SKP_GROUP_MAPS_MAX))
				return -1;
			if (bit == 262144)
				status->grouped_kstat_count = value;
			else
				status->grouped_map_count = value;
		}
		else if (span_is(key, "full_message_bytes") || span_is(key, "full_config_bytes")) {
			bit = span_is(key, "full_message_bytes") ? 1048576U : 2097152U;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value != (bit == 1048576U ? sizeof(full_message) : sizeof(full_message.config)))
				return -1;
		} else if (span_is(key, "group_redirect_isolation") || span_is(key, "group_mount_isolation") ||
			   span_is(key, "group_full_isolation")) {
			bit = span_is(key, "group_redirect_isolation") ? 4194304U :
				span_is(key, "group_mount_isolation") ? 8388608U : 16777216U;
			if (quoted || (!span_is(token, "true") && !span_is(token, "false")))
				return -1;
			if (bit == 4194304U) status->group_redirect = span_is(token, "true");
			else if (bit == 8388608U) status->group_mount = span_is(token, "true");
			else status->group_full = span_is(token, "true");
		} else if (span_is(key, "grouped_redirect_count") || span_is(key, "grouped_mount_count")) {
			bit = span_is(key, "grouped_redirect_count") ? 33554432U : 67108864U;
			if (quoted || decimal_span(token.text, token.n, &value) ||
			    value > (bit == 33554432U ? SKP_GROUP_REDIRECTS_MAX : SKP_GROUP_MOUNTS_MAX))
				return -1;
			if (bit == 33554432U) status->grouped_redirect_count = value;
			else status->grouped_mount_count = value;
		}
		if (bit && (seen & bit))
			return -1;
		seen |= bit;
		skip_space(&cursor);
		if (*cursor == '}') {
			cursor++;
			break;
		}
		if (*cursor++ != ',')
			return -1;
	}
	skip_space(&cursor);
	status->seen = seen;
	return *cursor || (seen & STATUS_LEGACY_FIELDS) != STATUS_LEGACY_FIELDS ? -1 : 0;
}

static int status_read(long fd, struct status_fields *status, usize *length)
{
	usize n = 0;
	long rc;
	char extra;

	while (n < STATUS_LIMIT) {
		rc = skp_policyctl_syscall(SC_READ, fd, (sysarg)(status_text + n), STATUS_LIMIT - n);
		if (rc == -4)
			continue;
		if (rc < 0)
			return (int)rc;
		if (!rc)
			break;
		if ((usize)rc > STATUS_LIMIT - n)
			return -90;
		n += rc;
	}
	if (n == STATUS_LIMIT) {
		do {
			rc = skp_policyctl_syscall(SC_READ, fd, (sysarg)&extra, 1);
		} while (rc == -4);
		if (rc)
			return rc < 0 ? (int)rc : -90;
	}
	status_text[n] = 0;
	/* Embedded NUL must not hide a suffix from the parser. */
	if (text_length(status_text) != n || status_parse(status_text, status))
		return -71; /* EPROTO */
	*length = n;
	return 0;
}

static void emit_u64(u64 value)
{
	char digits[24];
	usize n = 0;
	do {
		digits[n++] = (char)('0' + value % 10);
		value /= 10;
	} while (value);
	while (n)
		(void)emit(&digits[--n], 1);
}

/* An errno may be returned after an interrupted/ambiguous management write.
 * Check the same live session read-only, but never promote the failed write
 * into a confirmed commit: generation/facts are not an object-table digest.
 * The observed fields help the caller reconcile before any later write. */
static int unknown_write(long fd, long written)
{
	struct status_fields observed;
	usize length = 0;
	int rc = -5;
	u64 number = written < 0 ? (u64)-written : (u64)written;
	const char *text;

	if (skp_policyctl_syscall(SC_LSEEK, fd, 0, 0) == 0)
		rc = status_read(fd, &observed, &length);
	(void)skp_policyctl_syscall(SC_CLOSE, fd, 0, 0);
	text = rc ? "{\"result\":\"unknown\",\"reason\":\"policy_write_readback_failed_no_retry\",\"error\":" :
		"{\"result\":\"unknown\",\"reason\":\"policy_write_status_checked_no_retry\",\"error\":";
	(void)emit(text, text_length(text));
	emit_u64(number);
	text = rc ? ",\"observed\":false" : ",\"observed\":true,\"observed_generation\":\"";
	(void)emit(text, text_length(text));
	if (!rc) {
		emit_u64(observed.generation);
		text = "\",\"observed_facts_generation\":\"";
		(void)emit(text, text_length(text));
		emit_u64(observed.facts_generation);
		text = observed.skp ? "\",\"observed_mode\":\"skp\"" : "\",\"observed_mode\":\"upstream\"";
		(void)emit(text, text_length(text));
		if (observed.seen & 8192) {
			text = observed.full ? ",\"observed_object_families\":\"path,kstat,map,redirect,mount\"" :
				observed.objects ? ",\"observed_object_families\":\"path,kstat,map\"" :
				observed.paths ? ",\"observed_object_families\":\"path\"" :
				",\"observed_object_families\":\"upstream\"";
			(void)emit(text, text_length(text));
		}
	}
	(void)emit("}\n", 2);
	return 5;
}

int skp_policyctl_main(long argc, char **argv)
{
	struct status_fields status;
	usize i, length = 0, frame_bytes = sizeof(message);
	u64 expected = 0;
	int applying, applying_paths, applying_objects, applying_full, upstream, rc;
	long fd, written;
	char *frame = (char *)&message;
	char *path_frame = (char *)&paths_message;
	char *object_frame = (char *)&objects_message;
	char *full_frame = (char *)&full_message;

	for (i = 0; i < sizeof(message); ++i)
		frame[i] = 0;
	for (i = 0; i < sizeof(paths_message); ++i)
		path_frame[i] = 0;
	for (i = 0; i < sizeof(objects_message); ++i)
		object_frame[i] = 0;
	for (i = 0; i < sizeof(full_message); ++i)
		full_frame[i] = 0;
	if (argc == 2 && same(argv[1], "status")) {
		fd = skp_policyctl_syscall(SC_OPENAT, AT_CWD, (sysarg)SKP_POLICY_NODE,
			OPEN_RDONLY | OPEN_CLOEXEC | OPEN_NOFOLLOW);
		if (fd < 0)
			return error("error", "status_open", fd, 6);
		rc = status_read(fd, &status, &length);
		(void)skp_policyctl_syscall(SC_CLOSE, fd, 0, 0);
		if (rc)
			return error("error", "status_read", rc, 6);
		return emit(status_text, length) ? 6 : 0;
	}
	applying = argc == 4 && same(argv[1], "apply");
	applying_paths = argc == 4 && same(argv[1], "apply-paths");
	applying_objects = argc == 4 && (same(argv[1], "apply-objects") || same(argv[1], "--replace-objects"));
	applying_full = argc == 4 && (same(argv[1], "apply-full") || same(argv[1], "--replace-full"));
	upstream = argc == 3 && same(argv[1], "upstream");
	if (!applying && !applying_paths && !applying_objects && !applying_full && !upstream)
		return error("invalid_input", "usage_status_apply_apply_paths_apply_objects_apply_full_snapshot_generation_or_upstream_generation", 22, 2);
	if (decimal_span(argv[argc - 1], text_length(argv[argc - 1]), &expected))
		return error("invalid_input", "expected_generation", 22, 2);
	if (expected == U64_MAX_VALUE)
		return error("invalid_input", "generation_overflow", 75, 2);
	if (applying) {
		rc = snapshot_read(argv[2], &message.policy, sizeof(message.policy));
		if (rc)
			return error("invalid_input", "snapshot_read", rc, 2);
		rc = skp_subject_policy_validate(&message.policy);
		if (rc)
			return error("invalid_input", "snapshot_validation", rc, 2);
		if (message.policy.profile_count != 1 || message.policy.binding_count)
			return error("unsupported", "group_object_isolation", 95, 3);
	}
	if (applying_paths) {
		rc = snapshot_read(argv[2], &paths_message.config, sizeof(paths_message.config));
		if (rc)
			return error("invalid_input", "path_snapshot_read", rc, 2);
		rc = skp_group_paths_validate(&paths_message.config);
		if (rc)
			return error("invalid_input", "path_snapshot_validation", rc, 2);
		paths_message.magic = SKP_POLICY_MESSAGE_MAGIC;
		paths_message.version = SKP_POLICY_MESSAGE_VERSION;
		paths_message.size = sizeof(paths_message);
		paths_message.command = SKP_POLICY_REPLACE_PATHS;
		paths_message.expected_generation = expected;
		frame = path_frame;
		frame_bytes = sizeof(paths_message);
	}
	if (applying_objects) {
		rc = snapshot_read(argv[2], &objects_message.config, sizeof(objects_message.config));
		if (rc)
			return error("invalid_input", "object_snapshot_read", rc, 2);
		rc = skp_group_objects_validate(&objects_message.config);
		if (rc)
			return error("invalid_input", "object_snapshot_validation", rc, 2);
		objects_message.magic = SKP_POLICY_MESSAGE_MAGIC;
		objects_message.version = SKP_POLICY_MESSAGE_VERSION;
		objects_message.size = sizeof(objects_message);
		objects_message.command = SKP_POLICY_REPLACE_OBJECTS;
		objects_message.expected_generation = expected;
		frame = object_frame;
		frame_bytes = sizeof(objects_message);
	}
	if (applying_full) {
		rc = snapshot_read(argv[2], &full_message.config, sizeof(full_message.config));
		if (rc)
			return error("invalid_input", "full_snapshot_read", rc, 2);
		rc = skp_full_objects_validate(&full_message.config);
		if (rc)
			return error("invalid_input", "full_snapshot_validation", rc, 2);
		full_message.magic = SKP_POLICY_MESSAGE_MAGIC;
		full_message.version = SKP_POLICY_MESSAGE_VERSION;
		full_message.size = sizeof(full_message);
		full_message.command = SKP_POLICY_REPLACE_FULL;
		full_message.expected_generation = expected;
		frame = full_frame;
		frame_bytes = sizeof(full_message);
	}
	message.magic = SKP_POLICY_MESSAGE_MAGIC;
	message.version = SKP_POLICY_MESSAGE_VERSION;
	message.size = sizeof(message);
	message.command = applying ? SKP_POLICY_REPLACE : SKP_POLICY_USE_UPSTREAM;
	message.expected_generation = expected;
	fd = skp_policyctl_syscall(SC_OPENAT, AT_CWD, (sysarg)SKP_POLICY_NODE,
		OPEN_RDWR | OPEN_CLOEXEC | OPEN_NOFOLLOW);
	if (fd < 0)
		return error("rejected", "policy_open", fd, 4);
	/* The sole management write. In particular, EINTR is NOT retried. */
	written = skp_policyctl_syscall(SC_WRITE, fd, (sysarg)frame, frame_bytes);
	if (written != (long)frame_bytes)
		return unknown_write(fd, written);
	/* Preserve the exact manager session while inspecting the committed state. */
	if (skp_policyctl_syscall(SC_LSEEK, fd, 0, 0) != 0) {
		(void)skp_policyctl_syscall(SC_CLOSE, fd, 0, 0);
		return error("unknown", "readback_seek_no_retry", 5, 5);
	}
	rc = status_read(fd, &status, &length);
	(void)skp_policyctl_syscall(SC_CLOSE, fd, 0, 0);
	if (rc)
		return error("unknown", "readback_failed_no_retry", rc, 5);
	if (status.generation != expected + 1 || status.skp != (applying || applying_paths || applying_objects || applying_full) ||
	    status.facts_generation != (applying ? message.policy.facts_generation :
		applying_paths ? paths_message.config.subjects.facts_generation :
		applying_objects ? objects_message.config.paths.subjects.facts_generation :
		applying_full ? full_message.config.objects.paths.subjects.facts_generation : 0))
		return error("unknown", "readback_mismatch_no_retry", 116, 5);
	if (applying_paths && ((status.seen & STATUS_PATH_FIELDS) != STATUS_PATH_FIELDS ||
	    !status.paths || !status.group_paths || status.group_objects ||
	    status.grouped_path_count != paths_message.config.path_count ||
	    status.active_profile_count != paths_message.config.subjects.profile_count))
		return error("unknown", "path_readback_mismatch_no_retry", 116, 5);
	if (applying_objects && ((status.seen & STATUS_OBJECT_FIELDS) != STATUS_OBJECT_FIELDS ||
	    !status.objects || !status.group_paths || status.group_objects ||
	    !status.group_kstat || !status.group_map ||
	    status.grouped_path_count != objects_message.config.paths.path_count ||
	    status.grouped_kstat_count != objects_message.config.kstat_count ||
	    status.grouped_map_count != objects_message.config.map_count ||
	    status.active_profile_count != objects_message.config.paths.subjects.profile_count))
		return error("unknown", "object_readback_mismatch_no_retry", 116, 5);
	if (applying_full && ((status.seen & STATUS_FULL_FIELDS) != STATUS_FULL_FIELDS ||
	    !status.full || !status.group_paths || !status.group_objects ||
	    !status.group_kstat || !status.group_map || !status.group_redirect ||
	    !status.group_mount || !status.group_full ||
	    status.grouped_path_count != full_message.config.objects.paths.path_count ||
	    status.grouped_kstat_count != full_message.config.objects.kstat_count ||
	    status.grouped_map_count != full_message.config.objects.map_count ||
	    status.grouped_redirect_count != full_message.config.redirect_count ||
	    status.grouped_mount_count != full_message.config.mount_count ||
	    status.active_profile_count != full_message.config.objects.paths.subjects.profile_count))
		return error("unknown", "full_readback_mismatch_no_retry", 116, 5);
	return emit(status_text, length) ? 5 : 0;
}

#ifndef SKP_POLICYCTL_HOSTTEST
__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"\tmov x29, #0\n"
"\tldr x0, [sp]\n"
"\tadd x1, sp, #8\n"
"\tbl skp_policyctl_main\n"
"\tmov x8, #93\n"
"\tsvc #0\n"
);
#endif
