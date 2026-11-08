// SPDX-License-Identifier: GPL-2.0

#include <stddef.h>

#include <stddef.h>

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

#define SYS_write	64
#define SYS_openat	56
#define SYS_close	57
#define SYS_newfstatat	79
#define SYS_fstat	80
#define SYS_statx	291
#define SYS_sched_setaffinity 122

#define AT_FDCWD		(-100)
#define AT_EMPTY_PATH		0x1000
#define O_RDONLY		0

/* STATX_* request bits (include/uapi/linux/stat.h). */
#define STATX_BASIC_STATS	0x000007ffu

/* arm64 asm-generic struct stat (128 bytes). */
struct stat_native {
	u64 st_dev;		/* 0  */
	u64 st_ino;		/* 8  */
	u32 st_mode;		/* 16 */
	u32 st_nlink;		/* 20 */
	u32 st_uid;		/* 24 */
	u32 st_gid;		/* 28 */
	u64 st_rdev;		/* 32 */
	u64 __pad1;		/* 40 */
	s64 st_size;		/* 48 */
	s32 st_blksize;		/* 56 */
	s32 __pad2;		/* 60 */
	s64 st_blocks;		/* 64 */
	s64 st_atime;		/* 72 */
	u64 st_atime_nsec;	/* 80 */
	s64 st_mtime;		/* 88 */
	u64 st_mtime_nsec;	/* 96 */
	s64 st_ctime;		/* 104 */
	u64 st_ctime_nsec;	/* 112 */
	u32 __unused4;		/* 120 */
	u32 __unused5;		/* 124 */
};

_Static_assert(sizeof(struct stat_native) == 128, "native struct stat size");
_Static_assert(__builtin_offsetof(struct stat_native, st_ino) == 8, "st_ino offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_nlink) == 20, "st_nlink offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_size) == 48, "st_size offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_blocks) == 64, "st_blocks offset");

/* include/uapi/linux/stat.h: struct statx, 256 bytes. */
struct statx_timestamp {
	s64 tv_sec;
	u32 tv_nsec;
	s32 __reserved;
};

struct statx {
	u32 stx_mask;			/* 0x00 */
	u32 stx_blksize;		/* 0x04 */
	u64 stx_attributes;		/* 0x08 */
	u32 stx_nlink;			/* 0x10 */
	u32 stx_uid;			/* 0x14 */
	u32 stx_gid;			/* 0x18 */
	unsigned short stx_mode;	/* 0x1c */
	unsigned short __spare0[1];	/* 0x1e */
	u64 stx_ino;			/* 0x20 */
	u64 stx_size;			/* 0x28 */
	u64 stx_blocks;			/* 0x30 */
	u64 stx_attributes_mask;	/* 0x38 */
	struct statx_timestamp stx_atime;	/* 0x40 */
	struct statx_timestamp stx_btime;	/* 0x50 */
	struct statx_timestamp stx_ctime;	/* 0x60 */
	struct statx_timestamp stx_mtime;	/* 0x70 */
	u32 stx_rdev_major;		/* 0x80 */
	u32 stx_rdev_minor;		/* 0x84 */
	u32 stx_dev_major;		/* 0x88 */
	u32 stx_dev_minor;		/* 0x8c */
	u64 stx_mnt_id;			/* 0x90 */
	u32 stx_dio_mem_align;		/* 0x98 */
	u32 stx_dio_offset_align;	/* 0x9c */
	u64 __spare3[12];		/* 0xa0 */
};

_Static_assert(sizeof(struct statx) == 256, "struct statx size");
_Static_assert(__builtin_offsetof(struct statx, stx_mask) == 0x00, "stx_mask offset");
_Static_assert(__builtin_offsetof(struct statx, stx_nlink) == 0x10, "stx_nlink offset");
_Static_assert(__builtin_offsetof(struct statx, stx_ino) == 0x20, "stx_ino offset");
_Static_assert(__builtin_offsetof(struct statx, stx_size) == 0x28, "stx_size offset");
_Static_assert(__builtin_offsetof(struct statx, stx_dev_major) == 0x88, "stx_dev_major offset");

static struct stat_native st;
static struct statx sx;
static char out[1024];

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

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u32 putnum(char *dst, u32 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (u32)(v % 10));
		v /= 10;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static u32 putnum_s(char *dst, u32 pos, s64 v)
{
	if (v < 0) {
		dst[pos++] = '-';
		return putnum(dst, pos, (u64)(-v));
	}
	return putnum(dst, pos, (u64)v);
}

static u32 puthex(char *dst, u32 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

	dst[pos++] = '0';
	dst[pos++] = 'x';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = d[v & 0xf];
		v >>= 4;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static void emit(u32 pos)
{
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static void show_stat(const char *what, long rc, const struct stat_native *s)
{
	u32 pos = 0;

	pos = put(out, pos, what);
	if (rc < 0) {
		pos = put(out, pos, " rc=");
		pos = putnum_s(out, pos, -rc);
		pos = put(out, pos, " (failed)\n");
		emit(pos);
		return;
	}
	pos = put(out, pos, " rc=0 ino=");
	pos = putnum(out, pos, s->st_ino);
	pos = put(out, pos, " dev=");
	pos = puthex(out, pos, s->st_dev);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, s->st_nlink);
	pos = put(out, pos, " size=");
	pos = putnum_s(out, pos, s->st_size);
	pos = put(out, pos, " blksize=");
	pos = putnum_s(out, pos, s->st_blksize);
	pos = put(out, pos, " blocks=");
	pos = putnum_s(out, pos, s->st_blocks);
	pos = put(out, pos, " mtime=");
	pos = putnum_s(out, pos, s->st_mtime);
	pos = put(out, pos, "\n");
	emit(pos);
}

static void show_statx(long rc, u32 req_mask)
{
	u32 pos = 0;

	if (rc < 0) {
		pos = put(out, pos, "statx     : rc=");
		pos = putnum_s(out, pos, -rc);
		pos = put(out, pos, " (failed)\n");
		emit(pos);
		return;
	}
	pos = put(out, pos, "statx     : rc=0 req=");
	pos = puthex(out, pos, req_mask);
	pos = put(out, pos, " mask=");
	pos = puthex(out, pos, sx.stx_mask);
	pos = put(out, pos, " ino=");
	pos = putnum(out, pos, sx.stx_ino);
	pos = put(out, pos, " dev=");
	pos = putnum(out, pos, sx.stx_dev_major);
	pos = put(out, pos, ":");
	pos = putnum(out, pos, sx.stx_dev_minor);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, sx.stx_nlink);
	pos = put(out, pos, " size=");
	pos = putnum(out, pos, sx.stx_size);
	pos = put(out, pos, " blksize=");
	pos = putnum(out, pos, sx.stx_blksize);
	pos = put(out, pos, " blocks=");
	pos = putnum(out, pos, sx.stx_blocks);
	pos = put(out, pos, " mtime=");
	pos = putnum_s(out, pos, sx.stx_mtime.tv_sec);
	pos = put(out, pos, "\n");
	emit(pos);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	stat_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void stat_main(long argc, char **argv);
void stat_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	u32 req_mask = STATX_BASIC_STATS;
	long fd, rc;
	u32 pos = 0;
	int i;

	if (argc > 1)
		path = argv[1];
	if (argc > 2) {
		/* hex, with or without 0x */
		const char *p = argv[2];

		req_mask = 0;
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		for (i = 0; p[i]; i++) {
			u32 d;

			if (p[i] >= '0' && p[i] <= '9')
				d = (u32)(p[i] - '0');
			else if (p[i] >= 'a' && p[i] <= 'f')
				d = (u32)(p[i] - 'a') + 10;
			else if (p[i] >= 'A' && p[i] <= 'F')
				d = (u32)(p[i] - 'A') + 10;
			else
				break;
			req_mask = (req_mask << 4) | d;
		}
	}

	{
		unsigned long mask = 1ul << 7;

		sys6(SYS_sched_setaffinity, 0, (long)sizeof(mask), (long)&mask, 0, 0, 0);
	}

	pos = put(out, pos, "path=");
	pos = put(out, pos, path);
	pos = put(out, pos, "\n");
	emit(pos);

	/* 79: the path-based one, the same syscall `ls -li` and `toybox stat` use. */
	rc = sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st, 0, 0, 0);
	show_stat("newfstatat", rc, &st);

	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0) {
		pos = 0;
		pos = put(out, pos, "open failed rc=");
		pos = putnum_s(out, pos, -fd);
		pos = put(out, pos, "\n");
		emit(pos);
	} else {
		rc = sys6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0);
		show_stat("fstat     ", rc, &st);
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	}

	rc = sys6(SYS_statx, AT_FDCWD, (long)path, 0, (long)req_mask, (long)&sx, 0);
	show_statx(rc, req_mask);
	if (req_mask != STATX_BASIC_STATS) {
		rc = sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_BASIC_STATS, (long)&sx, 0);
		show_statx(rc, STATX_BASIC_STATS);
	}
}
