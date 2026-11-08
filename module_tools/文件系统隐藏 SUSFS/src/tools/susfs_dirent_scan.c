// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_dirent_scan - look for the placeholder record a post-hoc dirent filter leaves behind
 *
 * Two public detectors key off the same thing, so it is worth being able to check it directly:
 *
 *   - a chunk whose records are ALL hidden has no honest answer in a filter that rewrites what the
 *     kernel already wrote - returning 0 would read as end-of-directory and the caller would never
 *     see the visible entries of the next chunk.  So one record is left behind as a placeholder:
 *     d_ino = 0 with an empty name.
 *   - a caller can force "all hidden" for one chunk with a small buffer: a 56-byte buffer is below
 *     two minimum-size records, so the kernel hands over exactly one record per call.  If that one
 *     record is a hidden entry, a rewriting filter has to answer with the placeholder.
 *
 * Neither procfs nor sysfs ever emits d_ino 0, and a filter that decides *before* emitting (which
 * is what sus_dirent.c does) never produces one either: it drops the record and lets iterate_dir()
 * move on to the next entry inside the same call.  So finding a placeholder means the post-hoc
 * filter answered, and finding none means it did not.
 *
 * usage: susfs_dirent_scan [directory ...]      (default: /proc)
 *   Scans each directory twice - once with a 56-byte buffer and once with 32768 - and prints, per
 *   buffer size: the records returned, how many were placeholders, and the first syscall's result
 *   and errno.  Exit status is always 0; the counters are the report.
 *
 * Freestanding, static: no libc.  Run it as the uid whose view matters (an app uid for the
 * self-hide rules), since the module's gates are per-process.
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

#define SYS_openat	56
#define SYS_close	57
#define SYS_getdents64	61
#define SYS_write	64

#define AT_FDCWD	(-100)
#define O_RDONLY	0
/* arch/arm64/include/uapi/asm/fcntl.h overrides this for the 32-bit ABI: an aarch64 binary gets
 * 040000 (0x4000), not asm-generic's 00200000.  Getting it wrong makes openat() fail outright. */
#define O_DIRECTORY	0x4000

#define SMALL_BUF	56
#define BIG_BUF		32768

struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

/* A record has to at least hold the header plus one name byte: d_name starts right after the
 * 19-byte header, and the kernel aligns records to 8, so the smallest legal record is 24. */
#define MIN_RECLEN	24

static char out[512];
static char small[SMALL_BUF];
static char big[BIG_BUF];

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

static u32 put(u32 pos, const char *s)
{
	while (*s)
		out[pos++] = *s++;
	return pos;
}

static u32 putnum(u32 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		out[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (u32)(v % 10));
		v /= 10;
	}
	while (n)
		out[pos++] = tmp[--n];
	return pos;
}

static u32 putnum_s(u32 pos, s64 v)
{
	if (v < 0) {
		out[pos++] = '-';
		return putnum(pos, (u64)(-v));
	}
	return putnum(pos, (u64)v);
}

static void emit(u32 pos)
{
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

/* One pass over @dir with @bufsize.  Returns the placeholder count, and reports through the
 * out-parameters what the first syscall did. */
static long scan(const char *dir, char *buf, long bufsize, long *recs, long *first_n,
		 long *first_errno)
{
	long fd, n, off;
	long records = 0, placeholders = 0;
	int pass = 0;

	*recs = 0;
	*first_n = 0;
	*first_errno = 0;

	fd = sys6(SYS_openat, AT_FDCWD, (long)dir, O_RDONLY | O_DIRECTORY, 0, 0, 0);
	if (fd < 0) {
		*first_errno = -fd;
		return -1;
	}

	for (;;) {
		n = sys6(SYS_getdents64, fd, (long)buf, bufsize, 0, 0, 0);
		if (pass == 0) {
			*first_n = n;
			if (n < 0)
				*first_errno = -n;
		}
		pass++;
		if (n <= 0)
			break;

		off = 0;
		while (off < n) {
			struct linux_dirent64 *rec = (struct linux_dirent64 *)(buf + off);

			/* The record has to be big enough to hold its own header + a name byte, and it
			 * has to fit in what the kernel says it returned. */
			if (rec->d_reclen < MIN_RECLEN || off + rec->d_reclen > n)
				break;

			records++;
			/* The placeholder: ino 0 AND an empty name - both, like the detector does. */
			if (rec->d_ino == 0 && rec->d_name[0] == '\0')
				placeholders++;

			off += rec->d_reclen;
		}
	}

	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	*recs = records;
	return placeholders;
}

static void one(const char *dir)
{
	long recs, first_n, first_errno, ph;

	{
		u32 pos = 0;

		pos = put(pos, "dir ");
		pos = put(pos, dir);
		pos = put(pos, "\n");
		emit(pos);
	}

	ph = scan(dir, small, SMALL_BUF, &recs, &first_n, &first_errno);
	{
		u32 pos = 0;

		pos = put(pos, "  buf=56     records=");
		pos = putnum(pos, (u64)(ph < 0 ? 0 : recs));
		pos = put(pos, " placeholders=");
		pos = putnum(pos, (u64)(ph < 0 ? 0 : ph));
		pos = put(pos, " first_n=");
		pos = putnum_s(pos, first_n);
		if (first_errno) {
			pos = put(pos, " errno=");
			pos = putnum(pos, (u64)first_errno);
		}
		if (ph < 0)
			pos = put(pos, "  (open failed)");
		else if (ph > 0)
			pos = put(pos, "   *** PLACEHOLDER RECORD SEEN ***");
		pos = put(pos, "\n");
		emit(pos);
	}

	ph = scan(dir, big, BIG_BUF, &recs, &first_n, &first_errno);
	{
		u32 pos = 0;

		pos = put(pos, "  buf=32768  records=");
		pos = putnum(pos, (u64)(ph < 0 ? 0 : recs));
		pos = put(pos, " placeholders=");
		pos = putnum(pos, (u64)(ph < 0 ? 0 : ph));
		pos = put(pos, " first_n=");
		pos = putnum_s(pos, first_n);
		if (first_errno) {
			pos = put(pos, " errno=");
			pos = putnum(pos, (u64)first_errno);
		}
		if (ph < 0)
			pos = put(pos, "  (open failed)");
		else if (ph > 0)
			pos = put(pos, "   *** PLACEHOLDER RECORD SEEN ***");
		pos = put(pos, "\n");
		emit(pos);
	}
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	scan_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void scan_main(long argc, char **argv);
void scan_main(long argc, char **argv)
{
	long i;
	u32 pos;

	if (argc < 2) {
		one("/proc");
		one("/sys/module");
		return;
	}
	for (i = 1; i < argc; i++)
		one(argv[i]);

	pos = 0;
	pos = put(pos, "done\n");
	emit(pos);
}
