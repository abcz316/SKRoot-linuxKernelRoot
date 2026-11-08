// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_mapfile_probe - resolve this process's own map_files entries, N times
 *
 * Why a probe is needed at all: the map_files layer answers -ENOENT for a sus_map-hidden mapping,
 * and the callee (map_files_get_link) takes a reference for its caller before returning 0.  Whether
 * that reference is taken over again is invisible from userspace - the readlink answer is -ENOENT
 * either way, and a reference count is not something /proc reports.  What IS visible is whether the
 * dentry can still be reclaimed afterwards, which is exactly what decides whether an unmount of the
 * mapping's filesystem succeeds or comes back EBUSY.  So this probe's only job is to produce the
 * leak when there is one: map a file (so a vma exists), then resolve every entry of
 * /proc/self/map_files as many times as asked.
 *
 * usage: susfs_mapfile_probe <file> [iterations]        (default 200)
 *
 * exit status: 0 whenever it ran; the printed counters are the report.
 *   mapped=1        the file is mapped (keep it mapped for the whole run - the unlock happens on
 *                   process exit)
 *   iterations=N    directory listings performed
 *   readlinks=N     readlinkat() calls made
 *   enoent=N        of those, how many answered ENOENT - i.e. how many were hidden by the layer
 *   (a visible mapping answers with its own path, so a control run should show enoent=0)
 *
 * Freestanding, static: no libc, only syscalls.  It must run as the uid the sus_map gate cares
 * about (an app uid), which is also why it takes the file as an argument instead of opening one of
 * its own.
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

#define SYS_openat	56
#define SYS_close	57
#define SYS_getdents64	61
#define SYS_write	64
#define SYS_readlinkat	78
#define SYS_mmap	222

#define AT_FDCWD	(-100)
#define O_RDONLY	0
/* arch/arm64/include/uapi/asm/fcntl.h redefines these four for the 32-bit ABI, so an aarch64
 * binary gets ITS values - O_DIRECTORY is 040000 there, not asm-generic's 00200000.  Hard-coded
 * because this file takes no headers, and getting it wrong made openat() fail outright (the probe
 * then reported readlinks=0, which is what a broken run looks like). */
#define O_DIRECTORY	0x4000
#define PROT_READ	1
#define MAP_PRIVATE	2
#define ENOENT		2

/* include/uapi/linux/dirent.h, as getdents64 fills it on every arm64 kernel. */
struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static char out[512];
static char linkbuf[512];
static char dirbuf[8192];

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

static void emit(u32 pos)
{
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static u64 dec_to_u64(const char *p)
{
	u64 v = 0;

	while (*p >= '0' && *p <= '9')
		v = v * 10 + (u64)(*p++ - '0');
	return v;
}

static int is_dot(const char *n)
{
	if (n[0] != '.')
		return 0;
	if (n[1] == 0)
		return 1;
	return n[1] == '.' && n[2] == 0;
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	mapfile_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void mapfile_main(long argc, char **argv);
void mapfile_main(long argc, char **argv)
{
	const char *file = argc > 1 ? argv[1] : 0;
	long iters = argc > 2 ? (long)dec_to_u64(argv[2]) : 200;
	long fd, dirfd, n, r, i;
	long reads = 0, enoents = 0, mapped = 0;
	void *addr;
	u32 pos;

	if (!file) {
		pos = 0;
		pos = put(pos, "usage: susfs_mapfile_probe <file> [iterations]\n");
		emit(pos);
		return;
	}

	/* A vma on the target file is what map_files has to report, and what the callee hands over
	 * a reference to - so the mapping has to outlive every readlinkat() below. */
	fd = sys6(SYS_openat, AT_FDCWD, (long)file, O_RDONLY, 0, 0, 0);
	if (fd >= 0) {
		addr = (void *)sys6(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
		if ((long)addr > 0)
			mapped = 1;
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	}

	for (i = 0; i < iters; i++) {
		/* Re-opened every round: getdents64 has no rewind outside lseek, and /proc is cheap. */
		dirfd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/map_files",
			     O_RDONLY | O_DIRECTORY, 0, 0, 0);
		if (dirfd < 0)
			break;
		for (;;) {
			long off = 0;

			n = sys6(SYS_getdents64, dirfd, (long)dirbuf, (long)sizeof(dirbuf), 0, 0, 0);
			if (n <= 0)
				break;
			while (off < n) {
				struct linux_dirent64 *d = (struct linux_dirent64 *)(dirbuf + off);

				if (d->d_reclen == 0)
					break;
				if (!is_dot(d->d_name)) {
					r = sys6(SYS_readlinkat, dirfd, (long)d->d_name,
						 (long)linkbuf, (long)sizeof(linkbuf) - 1, 0, 0);
					reads++;
					if (r == -ENOENT)
						enoents++;
				}
				off += d->d_reclen;
			}
		}
		sys6(SYS_close, dirfd, 0, 0, 0, 0, 0);
	}

	pos = 0;
	pos = put(pos, "mapped=");
	pos = putnum(pos, (u64)mapped);
	pos = put(pos, " iterations=");
	pos = putnum(pos, (u64)iters);
	pos = put(pos, " readlinks=");
	pos = putnum(pos, (u64)reads);
	pos = put(pos, " enoent=");
	pos = putnum(pos, (u64)enoents);
	pos = put(pos, "\n");
	emit(pos);
}
