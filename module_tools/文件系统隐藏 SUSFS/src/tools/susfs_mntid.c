// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_mntid - look at the mount ids the way a detector would.
 *
 * Hiding a line from /proc/self/mountinfo is not enough on its own: the same
 * mount id is printed by /proc/self/fdinfo/N ("mnt_id:\t<i>") and returned by
 * statx(2) (stx_mnt_id).  An app needs no root to open an fd on a path, read its
 * fdinfo, call statx and compare both numbers against the ids mountinfo lists -
 * and any id that mountinfo never mentions is a mount that was hidden.
 *
 * This tool does exactly that and prints a verdict, so a rule can be measured
 * instead of assumed:
 *
 *   mountinfo: <lines> lines, <ids> distinct ids, <big> ids >= 2000000000
 *   path=<p> fd=<n> fdinfo_mnt_id=<i> in_mountinfo=<yes|NO>
 *   path=<p> statx_mnt_id=<i> in_mountinfo=<yes|NO>
 *   summary: fdinfo_missing=<n> statx_missing=<n>
 *
 * Freestanding like the other tools (no libc, -nostdlib -static-pie):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_mntid tools/susfs_mntid.c
 *
 * Usage: susfs_mntid <path> [path...]
 */

typedef unsigned long u64;
typedef long s64;

#define SYS_openat   56
#define SYS_close    57
#define SYS_read     63
#define SYS_write    64
#define SYS_exit     93
#define SYS_statx    291

#define AT_FDCWD    (-100)
#define O_RDONLY    0
#define STATX_MNT_ID 0x00001000

#define MI_MAX 65536
#define ID_MAX 1024
#define BIG_ID 2000000000ull

/* uapi struct statx, only to get stx_mnt_id at the layout Linux uses. */
struct statx_ts {
	s64 tv_sec;
	unsigned tv_nsec;
	int __reserved;
};

struct statx_min {
	unsigned stx_mask;
	unsigned stx_blksize;
	u64 stx_attributes;
	unsigned stx_nlink;
	unsigned stx_uid;
	unsigned stx_gid;
	unsigned short stx_mode;
	unsigned short __spare0[1];
	u64 stx_ino;
	u64 stx_size;
	u64 stx_blocks;
	u64 stx_attributes_mask;
	struct statx_ts stx_atime;
	struct statx_ts stx_btime;
	struct statx_ts stx_ctime;
	struct statx_ts stx_mtime;
	unsigned stx_rdev_major;
	unsigned stx_rdev_minor;
	unsigned stx_dev_major;
	unsigned stx_dev_minor;
	u64 stx_mnt_id;
	unsigned stx_dio_mem_align;
	unsigned stx_dio_offset_align;
	u64 __spare3[12];
};

static char out[4096];
static char mi[MI_MAX];
static char small[4096];
static struct statx_min stx;
static u64 ids[ID_MAX];
static int n_ids;

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory", "cc");
	return x0;
}

static u64 put(char *dst, u64 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u64 putnum(char *dst, u64 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

/* Reads a whole (small) proc file, returns bytes or -1. */
static long read_file(const char *path, char *buf, u64 cap)
{
	long fd, n, total = 0;

	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0)
		return -1;
	while (total < (long)cap - 1) {
		n = sys6(SYS_read, fd, (long)(buf + total), (long)(cap - 1 - total), 0, 0, 0);
		if (n <= 0)
			break;
		total += n;
	}
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	buf[total] = 0;
	return total;
}

static int starts_with(const char *s, const char *prefix)
{
	while (*prefix)
		if (*s++ != *prefix++)
			return 0;
	return 1;
}

/* fdigits: parse a decimal number at s, returns chars consumed. */
static int parse_dec(const char *s, u64 *out)
{
	u64 v = 0;
	int n = 0;

	while (s[n] >= '0' && s[n] <= '9' && n < 18) {
		v = v * 10 + (u64)(s[n] - '0');
		n++;
	}
	*out = v;
	return n;
}

static int in_mountinfo(u64 id)
{
	int i;

	for (i = 0; i < n_ids; i++)
		if (ids[i] == id)
			return 1;
	return 0;
}

/* First column of every mountinfo line is the mount id. */
static void load_mountinfo(void)
{
	long n = read_file("/proc/self/mountinfo", mi, sizeof(mi));
	long i = 0;
	u64 biggest = 0, n_big = 0;

	if (n <= 0)
		return;
	while (i < n) {
		u64 id = 0;

		if (parse_dec(&mi[i], &id) > 0) {
			if (n_ids < ID_MAX && !in_mountinfo(id))
				ids[n_ids++] = id;
			if (id > biggest)
				biggest = id;
			if (id >= BIG_ID)
				n_big++;
		}
		while (i < n && mi[i] != '\n')
			i++;
		i++;
	}
	{
		u64 pos = 0;

		pos = put(out, pos, "mountinfo: idlist=");
		pos = putnum(out, pos, (u64)n_ids);
		pos = put(out, pos, " max_id=");
		pos = putnum(out, pos, biggest);
		pos = put(out, pos, " ids_over_2e9=");
		pos = putnum(out, pos, n_big);
		pos = put(out, pos, "\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
	}
}

static int fdinfo_mnt_id(int fd, u64 *out_id)
{
	char path[64];
	u64 pos = 0, i;
	long n;

	pos = put(path, pos, "/proc/self/fdinfo/");
	pos = putnum(path, pos, (u64)fd);
	path[pos] = 0;
	n = read_file(path, small, sizeof(small));
	if (n <= 0)
		return -1;
	for (i = 0; i + 8 < (u64)n; i++) {
		if (!starts_with(&small[i], "mnt_id:\t"))
			continue;
		if (parse_dec(&small[i + 8], out_id) > 0)
			return 0;
	}
	return -1;
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	mntid_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void mntid_main(long argc, char **argv);

void mntid_main(long argc, char **argv)
{
	u64 fdinfo_missing = 0, statx_missing = 0;
	long i;

	load_mountinfo();

	for (i = 1; i < argc; i++) {
		const char *path = argv[i];
		u64 pos = 0, id = 0;
		long fd;

		fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
		if (fd < 0) {
			pos = put(out, pos, "path=");
			pos = put(out, pos, path);
			pos = put(out, pos, " open_failed\n");
			sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
			continue;
		}

		if (!fdinfo_mnt_id((int)fd, &id)) {
			int ok = in_mountinfo(id);

			if (!ok)
				fdinfo_missing++;
			pos = put(out, pos, "path=");
			pos = put(out, pos, path);
			pos = put(out, pos, " fd=");
			pos = putnum(out, pos, (u64)fd);
			pos = put(out, pos, " fdinfo_mnt_id=");
			pos = putnum(out, pos, id);
			pos = put(out, pos, ok ? " in_mountinfo=yes\n" : " in_mountinfo=NO\n");
			sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
			pos = 0;
		}
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);

		if (sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_MNT_ID,
			 (long)&stx, 0) == 0) {
			int ok = in_mountinfo(stx.stx_mnt_id);

			if (!ok)
				statx_missing++;
			pos = put(out, pos, "path=");
			pos = put(out, pos, path);
			pos = put(out, pos, " statx_mnt_id=");
			pos = putnum(out, pos, stx.stx_mnt_id);
			pos = put(out, pos, ok ? " in_mountinfo=yes\n" : " in_mountinfo=NO\n");
			sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
		}
	}

	{
		u64 pos = 0;

		pos = put(out, pos, "summary: fdinfo_missing=");
		pos = putnum(out, pos, fdinfo_missing);
		pos = put(out, pos, " statx_missing=");
		pos = putnum(out, pos, statx_missing);
		pos = put(out, pos, "\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
	}
}
