// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_open_probe - what did that open really hand back?
 *
 * The module's layers answer opens themselves in two places (the O_PATH post-check takes a
 * descriptor out of the caller's table, and open_redirect's name layer opens the target and
 * installs a descriptor of its own), so the only way to tell what a caller actually got is to
 * ask the questions a caller asks:
 *
 *   - the descriptor number, or the errno;
 *   - fcntl(F_GETFD), where FD_CLOEXEC has to be set exactly when the caller asked for
 *     O_CLOEXEC - the kernel takes that bit from the UNSTRIPPED flags when it allocates the
 *     descriptor (fs/open.c: get_unused_fd_flags(how.flags & O_CLOEXEC));
 *   - fcntl(F_GETFL), which reads f_flags and therefore shows the flags the file was opened
 *     with, O_PATH and O_LARGEFILE included;
 *   - fstat(fd), the question that answers EBADF if the number is no longer in the table;
 *   - readlink(/proc/self/fd/<n>), which names the file the descriptor really refers to -
 *     that is what separates a followed symlink from the link itself.
 *
 * Freestanding and static: the syscall numbers and the two structures below are the only ABI
 * this file depends on, so it runs anywhere the module does (arm64).
 *
 * usage: susfs_open_probe <path> [flags_hex] [mode_dec] [--openat2] [--both] [--resolve=hex]
 *   flags defaults to 0 (O_RDONLY), mode to 0.
 *   Some flags worth asking for by hand:
 *     O_PATH|O_CREAT|O_EXCL 0x2000c0   what does the kernel do with the other two bits?
 *     O_PATH                0x200000
 *     O_RDONLY|O_CLOEXEC    0x80000
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

#define SYS_fcntl	25
#define SYS_openat	56
#define SYS_close	57
#define SYS_write	64
#define SYS_readlinkat	78
#define SYS_fstat	80
#define SYS_openat2	437
#define SYS_sched_setaffinity	122

#define AT_FDCWD	(-100)
#define F_GETFD		1
#define F_GETFL		3
#define FD_CLOEXEC	1

struct open_how {
	u64 flags;
	u64 mode;
	u64 resolve;
};

_Static_assert(sizeof(struct open_how) == 24, "open_how is 24 bytes (OPEN_HOW_SIZE_VER0)");

/* arm64 asm-generic struct stat, 128 bytes: the kernel writes all of it, so it has to be all
 * here even though only st_ino/st_mode are printed. */
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
_Static_assert(__builtin_offsetof(struct stat_native, st_mode) == 16, "st_mode offset");

static struct stat_native st;
static char out[2048];
static char linkbuf[512];
static char fdpath[32];

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

static u32 puthex(u32 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

	out[pos++] = '0';
	out[pos++] = 'x';
	if (!v) {
		out[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = d[v & 0xf];
		v >>= 4;
	}
	while (n)
		out[pos++] = tmp[--n];
	return pos;
}

static void emit(u32 pos)
{
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static int same(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static int starts_with(const char *s, const char *p)
{
	while (*p) {
		if (*s++ != *p++)
			return 0;
	}
	return 1;
}

static u64 hex_to_u64(const char *p)
{
	u64 v = 0;

	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;
	for (; *p; p++) {
		u32 d;

		if (*p >= '0' && *p <= '9')
			d = (u32)(*p - '0');
		else if (*p >= 'a' && *p <= 'f')
			d = (u32)(*p - 'a') + 10;
		else if (*p >= 'A' && *p <= 'F')
			d = (u32)(*p - 'A') + 10;
		else
			break;
		v = (v << 4) | d;
	}
	return v;
}

static u64 dec_to_u64(const char *p)
{
	u64 v = 0;

	while (*p >= '0' && *p <= '9')
		v = v * 10 + (u64)(*p++ - '0');
	return v;
}

/* One open, then every question that can be asked about what came back. */
static void probe(const char *path, u64 flags, u64 mode, u64 resolve, int use_openat2)
{
	u32 pos;
	long fd, r;

	if (use_openat2) {
		struct open_how how;

		how.flags = flags;
		how.mode = mode;
		how.resolve = resolve;
		fd = sys6(SYS_openat2, AT_FDCWD, (long)path, (long)&how,
			  (long)sizeof(how), 0, 0);
	} else {
		fd = sys6(SYS_openat, AT_FDCWD, (long)path, (long)flags, (long)mode, 0, 0);
	}

	pos = 0;
	pos = put(pos, use_openat2 ? "openat2  flags=" : "openat   flags=");
	pos = puthex(pos, flags);
	if (use_openat2) {
		pos = put(pos, " resolve=");
		pos = puthex(pos, resolve);
	}
	if (fd < 0) {
		pos = put(pos, " -> failed, errno=");
		pos = putnum_s(pos, -fd);
		pos = put(pos, "\n");
		emit(pos);
		return;
	}
	pos = put(pos, " -> fd=");
	pos = putnum(pos, (u64)fd);
	pos = put(pos, "\n");
	emit(pos);

	r = sys6(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0);
	pos = 0;
	pos = put(pos, "  F_GETFD  = ");
	if (r < 0) {
		pos = put(pos, "errno=");
		pos = putnum_s(pos, -r);
	} else {
		pos = puthex(pos, (u64)r);
		pos = put(pos, (r & FD_CLOEXEC) ? "  FD_CLOEXEC set" : "  FD_CLOEXEC MISSING");
	}
	pos = put(pos, "\n");
	emit(pos);

	r = sys6(SYS_fcntl, fd, F_GETFL, 0, 0, 0, 0);
	pos = 0;
	pos = put(pos, "  F_GETFL  = ");
	if (r < 0) {
		pos = put(pos, "errno=");
		pos = putnum_s(pos, -r);
	} else {
		pos = puthex(pos, (u64)r);
	}
	pos = put(pos, "\n");
	emit(pos);

	r = sys6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0);
	pos = 0;
	pos = put(pos, "  fstat    = ");
	if (r < 0) {
		pos = put(pos, "errno=");
		pos = putnum_s(pos, -r);
	} else {
		pos = put(pos, "ok ino=");
		pos = putnum(pos, st.st_ino);
		pos = put(pos, " mode=");
		pos = puthex(pos, st.st_mode);
	}
	pos = put(pos, "\n");
	emit(pos);

	/* /proc/self/fd/<n> is a symlink to the file the descriptor refers to, so this line is
	 * what tells a followed symlink from the link itself. */
	{
		u32 n = 0;
		const char *pre = "/proc/self/fd/";
		u32 k;

		for (k = 0; pre[k]; k++)
			fdpath[n++] = pre[k];
		n = putnum(n, (u64)fd);
		fdpath[n] = 0;
	}

	r = sys6(SYS_readlinkat, AT_FDCWD, (long)fdpath, (long)linkbuf,
		 (long)sizeof(linkbuf) - 1, 0, 0);
	pos = 0;
	pos = put(pos, "  fdpath   = ");
	if (r < 0) {
		pos = put(pos, "readlink errno=");
		pos = putnum_s(pos, -r);
	} else {
		linkbuf[r] = 0;
		pos = put(pos, "\"");
		pos = put(pos, linkbuf);
		pos = put(pos, "\"");
	}
	pos = put(pos, "\n");
	emit(pos);

	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	open_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void open_main(long argc, char **argv);
void open_main(long argc, char **argv)
{
	const char *path = 0;
	u64 flags = 0;
	u64 mode = 0;
	u64 resolve = 0;
	int use_openat2 = 0;
	int both = 0;
	int flags_given = 0;
	int mode_given = 0;
	long i;
	u32 pos;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (same(a, "--openat2")) {
			use_openat2 = 1;
		} else if (same(a, "--both")) {
			both = 1;
		} else if (starts_with(a, "--resolve=")) {
			resolve = hex_to_u64(a + 10);
		} else if (!path) {
			path = a;
		} else if (!flags_given) {
			flags = hex_to_u64(a);
			flags_given = 1;
		} else if (!mode_given) {
			mode = dec_to_u64(a);
			mode_given = 1;
		}
	}

	pos = 0;
	pos = put(pos, "path     = ");
	if (path) {
		/* Bounded: out[] is 2048 bytes while argv[1] can be far longer (MAX_ARG_STRLEN is
		 * 128 KiB), so copying the whole argument here would run past the buffer and spill
		 * the globals next to it. */
		u32 n = 0;

		while (path[n] && n < 400)
			out[pos++] = path[n++];
		if (path[n])
			pos = put(pos, "... (truncated)");
	} else {
		pos = put(pos, "(none - usage: susfs_open_probe <path> [flags_hex] [mode_dec] [--openat2|--both] [--resolve=hex])");
	}
	pos = put(pos, "\n");
	emit(pos);

	if (!path)
		return;

	/* One cpu, so two calls in a row are not scheduled on different cores - the layers this
	 * probe is pointed at are all per-task, but a stable run makes the output comparable. */
	{
		unsigned long mask = 1ul << 7;

		sys6(SYS_sched_setaffinity, 0, (long)sizeof(mask), (long)&mask, 0, 0, 0);
	}

	if (both || !use_openat2)
		probe(path, flags, mode, resolve, 0);
	if (both || use_openat2)
		probe(path, flags, mode, resolve, 1);
}
