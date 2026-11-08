// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_compat_stat - a 32-bit (AArch32) caller, to test the compat stat path.
 *
 * The kernel-side ABI audit found that the module was spoofing the WRONG compat
 * structure: __NR_fstatat64 (327) and __NR_fstat64 (197) are mapped to
 * sys_fstatat64/sys_fstat64, which fill `struct stat64` (arch/arm64/include/asm/
 * stat.h:19-48) - not `struct compat_stat`, which belongs to __NR_stat/lstat/fstat
 * (106/107/108).  Nothing in the repository could have caught that, because no
 * 32-bit client existed: a 64-bit process cannot make a 32-bit syscall here.
 *
 * This is that client.  It calls fstatat64 (and fstat64) and prints what came
 * back, so a rule's spoofed ino/dev/size/nlink can be compared against the same
 * rule observed from a 64-bit caller.
 *
 * It also walks one directory through BOTH of the listing interfaces an AArch32
 * caller has - getdents64 (217, mapped to the native sys_getdents64) and getdents
 * (141, whose own compat body has a different record layout) - because only a
 * 32-bit caller can reach the second one at all.
 *
 * The struct below must use the SAME alignment the kernel uses.  compat_u64/
 * compat_s64 are `__attribute__((aligned(4)))` only when
 * CONFIG_COMPAT_FOR_U64_ALIGNMENT is set (include/asm-generic/compat.h), and that
 * option is selected by the 32-bit arm architecture only - on arm64 the plain
 * typedefs apply, so the u64 members keep their natural 8-byte alignment and
 * sizeof(struct stat64) is 104, with st_size at +48 and st_ino at +96.
 *
 * Marking this struct `packed` (the first version of this client did) silently
 * makes the client disagree with the kernel: a 6-byte file came back as
 * size=25769803776 = 6 << 32, because the low half of the field was read from the
 * padding the kernel had left.  The size check printed below is what caught it.
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *     clang --target=armv7a-linux-androideabi -march=armv7-a -O2 -nostdlib \
 *           -static-pie -fno-stack-protector -fno-builtin -fuse-ld=lld \
 *           -Wl,-e,_start -o susfs_compat_stat tools/susfs_compat_stat.c
 *
 * Usage: susfs_compat_stat <path> [dir] [needle]
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_lseek 19
#define __NR_fstatat64 327
#define __NR_fstat64 197
#define __NR_stat64 195
#define __NR_lstat64 196
#define AT_FDCWD (-100)

struct stat64_compat {
	u64 st_dev;			/* 0  */
	unsigned char __pad0[4];	/* 8  */
	u32 __st_ino;			/* 12 (filled by the kernel) */
	u32 st_mode;			/* 16 */
	u32 st_nlink;			/* 20 */
	u32 st_uid;			/* 24 */
	u32 st_gid;			/* 28 */
	u64 st_rdev;			/* 32 */
	unsigned char __pad3[4];	/* 40 */
	s64 st_size;			/* 48 (8-byte aligned on arm64) */
	u32 st_blksize;			/* 56 */
	u64 st_blocks;			/* 64 */
	u32 st_atime;			/* 72 */
	u32 st_atime_nsec;		/* 76 */
	u32 st_mtime;			/* 80 */
	u32 st_mtime_nsec;		/* 84 */
	u32 st_ctime;			/* 88 */
	u32 st_ctime_nsec;		/* 92 */
	u64 st_ino;			/* 96 (left alone: STAT64_HAS_BROKEN_ST_INO) */
};

/* The layout claim, checked at compile time: if armv7's default alignment ever
 * differed from the arm64 kernel's view, the client would be measuring itself. */
_Static_assert(sizeof(struct stat64_compat) == 104, "stat64 size");
_Static_assert(__builtin_offsetof(struct stat64_compat, __st_ino) == 12, "stat64 __st_ino");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_size) == 48, "stat64 st_size");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_blocks) == 64, "stat64 st_blocks");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_ctime_nsec) == 92, "stat64 st_ctime_nsec");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_ino) == 96, "stat64 st_ino");

static struct stat64_compat st;
static char out[512];

static long sys4(long n, long a, long b, long c, long d)
{
	register long r7 __asm__("r7") = n;
	register long r0 __asm__("r0") = a;
	register long r1 __asm__("r1") = b;
	register long r2 __asm__("r2") = c;
	register long r3 __asm__("r3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(r0)
			 : "r"(r7), "r"(r1), "r"(r2), "r"(r3)
			 : "memory", "cc");
	return r0;
}

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

/* armv7 has no 64-bit division instruction, and a freestanding binary has no
 * libgcc, so `v / 10` would pull in __aeabi_uldivmod and fail to link (it did).
 * Shift-subtract long division instead: 64 iterations, no library call. */
static u64 u64_div10(u64 v, u64 *rem)
{
	u64 q = 0, r = 0;
	int i;

	for (i = 63; i >= 0; i--) {
		r = (r << 1) | ((v >> i) & 1);
		if (r >= 10) {
			r -= 10;
			q |= (1ull << i);
		}
	}
	*rem = r;
	return q;
}

static u32 putnum(char *dst, u32 pos, u64 v, int neg)
{
	char tmp[24];
	int n = 0;

	if (neg)
		dst[pos++] = '-';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		u64 rem;

		v = u64_div10(v, &rem);
		tmp[n++] = (char)('0' + (u32)rem);
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
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

static void show(const char *what, long rc)
{
	u32 pos = 0;

	pos = put(out, pos, what);
	if (rc < 0) {
		pos = put(out, pos, " rc=");
		pos = putnum(out, pos, (u64)(-rc), 0);
		pos = put(out, pos, " (failed)\n");
		sys4(SYS_write, 1, (long)out, pos, 0);
		return;
	}
	pos = put(out, pos, " ino=");
	pos = putnum(out, pos, st.st_ino, 0);
	pos = put(out, pos, " broken_ino=");
	pos = putnum(out, pos, st.__st_ino, 0);
	pos = put(out, pos, " dev=");
	pos = puthex(out, pos, st.st_dev);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, st.st_nlink, 0);
	pos = put(out, pos, " size=");
	pos = putnum(out, pos, (u64)st.st_size, 0);
	pos = put(out, pos, " mtime=");
	pos = putnum(out, pos, (u64)st.st_mtime, 0);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
}

/* ---- the two listing ABIs an AArch32 caller can use ----
 *
 * This is why a 32-bit client is needed for more than stat: the AArch32 table has
 * getdents64 (217) pointing at the NATIVE sys_getdents64 - so the 64-bit path already
 * covers it - and a SEPARATE getdents (141) whose body has its own record layout.
 * Upstream calls that body __do_compat_sys_getdents (COMPAT_SYSCALL_DEFINE3 in
 * fs/readdir.c).  The module names neither body: it rides the shared sys_exit
 * tracepoint and decides by (syscall number, caller ABI), so both numbers reach it
 * from here.  The two layouts:
 *
 *   getdents64: struct linux_dirent64      { u64 ino; s64 off; u16 reclen; u8 type; char name[]; }
 *               -> reclen at +16, name at +19
 *   getdents:   struct compat_linux_dirent { u32 ino; u32 off; u16 reclen; char name[]; }
 *               -> reclen at +8,  name at +10
 *
 * A hidden entry must be gone from both.  Fields are read byte-wise: the buffer is
 * a char array, and unaligned 64-bit loads are not worth relying on here. */
#define __NR_getdents 141
#define __NR_getdents64 217
#define DIRBUF 4096
/* The buffer is poisoned before every read.  The module rewrites the length getdents64 hands
 * back (syscall_set_return_value) to the length of the COMPACTED chain, so the residue it left
 * behind sits past that length by construction - and so does whatever a previous, longer read
 * left in the buffer.  A pattern that cannot occur in a record field or a name keeps the two
 * apart: a hit can then only come from bytes this read actually wrote. */
#define DIRBUF_POISON 0xA5

static char dirbuf[DIRBUF];

static int name_is(const char *p, const char *needle)
{
	if (!needle || !needle[0])
		return 0;
	while (*needle) {
		if (*p++ != *needle++)
			return 0;
	}
	return *p == 0;
}

/* Could this byte be part of a file name?  Used to reject a needle that occurs inside a
 * longer, visible name ("myopen600.bak" must not count as "open600"). */
static int is_name_byte(unsigned char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') || c == '_' || c == '-' || c == '.';
}

static void poison_dirbuf(void)
{
	long i;

	for (i = 0; i < DIRBUF; i++)
		dirbuf[i] = (char)DIRBUF_POISON;
}

/* Occurrence count over the WHOLE buffer, not just over the part the record chain describes.
 * A caller is free to ignore the length getdents64 returned and search the bytes itself, so a
 * name that is only gone from the CHAIN is not hidden.  That is how the module used to drop an
 * entry: it compacted the chain and left the dropped record's bytes - the whole name, its
 * d_ino and its d_off - in the tail it no longer described, which is invisible to the record
 * walk below (it stops at n) and visible to this counter.
 *
 * A match only counts at a name boundary: the byte before it must not be a name character.
 * What precedes a record's own d_name is the buffer start, the d_type byte (0..15), the HIGH
 * byte of d_reclen in the 32-bit layout (the name field starts at offset 10 and a record stays
 * under 269 bytes, so that byte is 0x00 or 0x01), or a placeholder's zeroed name[0].  None of
 * them is a name character, so this drops the "inside a longer name" false positives without
 * hiding a record the module left behind.  A plain NUL test would be wrong here: at
 * reclen >= 256 that byte is 0x01, not NUL, and the hit would be missed. */
static u32 scan_raw(const char *buf, long n, const char *needle)
{
	u32 hits = 0;
	long i, k, nl = 0;

	if (!needle || !needle[0])
		return 0;
	while (needle[nl])
		nl++;
	for (i = 0; i + nl <= n; i++) {
		if (i && is_name_byte((unsigned char)buf[i - 1]))
			continue;
		for (k = 0; k < nl; k++)
			if (buf[i + k] != needle[k])
				break;
		if (k == nl)
			hits++;
	}
	return hits;
}

static u32 scan_dir(long fd, int compat, const char *needle, u32 *entries,
		    u32 *raw_hits, u32 *tail_hits)
{
	u32 matches = 0;
	long n;

	*entries = 0;
	*raw_hits = 0;
	*tail_hits = 0;
	for (;;) {
		long off = 0;

		poison_dirbuf();
		n = sys4(compat ? __NR_getdents : __NR_getdents64,
			 fd, (long)dirbuf, DIRBUF, 0);
		if (n <= 0)
			break;

		/* Both raw counts cover the WHOLE buffer, not [0, n): n is the length the module
		 * chose to report, and the bytes it no longer describes - where a dropped record
		 * survives - are exactly the ones past n.  `tail_hits` looks for the name without
		 * its first byte: the all-hidden placeholder zeroes name[0], and "susfs_kstat"
		 * then sits in the buffer as "usfs_kstat" - a name the full-needle search cannot
		 * see. */
		*raw_hits += scan_raw(dirbuf, DIRBUF, needle);
		if (needle && needle[0])
			*tail_hits += scan_raw(dirbuf, DIRBUF, needle + 1);

		while (off < n) {
			u32 reclen, nameoff;

			/* Bound BEFORE reading the field: reclen is what the bound check
			 * below uses, so reading it first can run past the buffer (and a
			 * garbage length would then classify a hidden entry as visible - a
			 * false negative in the tool that is supposed to be the evidence). */
			if (off + (compat ? 10 : 18) > n)
				break;

			if (compat) {
				reclen = (unsigned char)dirbuf[off + 8] |
					 ((u32)(unsigned char)dirbuf[off + 9] << 8);
				nameoff = 10;
			} else {
				reclen = (unsigned char)dirbuf[off + 16] |
					 ((u32)(unsigned char)dirbuf[off + 17] << 8);
				nameoff = 19;
			}
			if (reclen < nameoff + 1 || off + (long)reclen > n)
				break;
			(*entries)++;
			if (name_is(dirbuf + off + nameoff, needle))
				matches++;
			off += reclen;
		}
	}
	return matches;
}

/* What one chunk tells a caller, at four levels of trust in the returned length:
 *   entries     - records the chain describes (what a readdir() loop walks)
 *   needle_hits - times the needle appears as a complete record name in that chain
 *   raw_hits    - times the needle appears at the START of a name anywhere in the buffer,
 *                 including the bytes past the returned length (the buffer is poisoned before
 *                 each read, so what is counted is this read's bytes): a process that ignores
 *                 the length, or scans the buffer for names, reads the hidden name back here.
 *                 A visible name that merely contains the needle is not counted; one that
 *                 starts with it still is (a false positive in the safe direction)
 *   tail_hits   - times the needle without its first byte appears in the same bytes, which
 *                 is all that a placeholder zeroing name[0] leaves of it
 * A hidden entry must score 0 on the last three; only then is it gone from the buffer and
 * not merely missing from the chain. */
static void show_dirents(long dirfd, int compat, const char *needle)
{
	u32 pos = 0, entries = 0, raw_hits = 0, tail_hits = 0;
	u32 matches = scan_dir(dirfd, compat, needle, &entries, &raw_hits, &tail_hits);

	pos = put(out, pos, compat ? "getdents(141)  " : "getdents64(217)");
	pos = put(out, pos, " entries=");
	pos = putnum(out, pos, entries, 0);
	pos = put(out, pos, " needle_hits=");
	pos = putnum(out, pos, matches, 0);
	pos = put(out, pos, " raw_hits=");
	pos = putnum(out, pos, raw_hits, 0);
	pos = put(out, pos, " name_tail_hits=");
	pos = putnum(out, pos, tail_hits, 0);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	fp, #0\n"
"	ldr	r0, [sp]\n"
"	add	r1, sp, #4\n"
"	bl	compat_main\n"
"	mov	r7, #1\n"
"	svc	#0\n"
);

void compat_main(long argc, char **argv);
void compat_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	const char *dir = "/data/local/tmp/dac_probe";
	const char *needle = "open600";
	long fd, rc;
	u32 pos = 0;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		dir = argv[2];
	if (argc > 3)
		needle = argv[3];

	pos = put(out, pos, "struct stat64 size=");
	pos = putnum(out, pos, (u64)sizeof(st), 0);
	pos = put(out, pos, " (expect 104; 96 would mean a 4-byte-aligned layout)\n");
	sys4(SYS_write, 1, (long)out, pos, 0);

	rc = sys4(__NR_fstatat64, AT_FDCWD, (long)path, (long)&st, 0);
	show("fstatat64", rc);

	/* stat64/lstat64 take the path (and fstat64 the fd) with statbuf in the SECOND argument -
	 * the same struct stat64 the two calls above fill.  Without these three the client could
	 * not see that the kstat layer's compat dispatch used to handle only 327/197: a 32-bit
	 * caller's stat64()/lstat64()/fstat64() answered with the real ino/dev/size while its
	 * fstatat64() answered with the spoofed ones. */
	rc = sys4(__NR_stat64, (long)path, (long)&st, 0, 0);
	show("stat64   ", rc);

	rc = sys4(__NR_lstat64, (long)path, (long)&st, 0, 0);
	show("lstat64  ", rc);

	fd = sys4(SYS_open, (long)path, 0, 0, 0);
	if (fd >= 0) {
		rc = sys4(__NR_fstat64, fd, (long)&st, 0, 0);
		show("fstat64  ", rc);
	}

	/* Both listing interfaces, on the directory that holds the hidden entry: the needle
	 * must be missing from BOTH - and, for a rule that hides it, from the raw bytes of
	 * every chunk too (raw_hits=0, name_tail_hits=0), which is the difference between
	 * "the chain does not mention it" and "the buffer does not contain it". */
	fd = sys4(SYS_open, (long)dir, 0, 0, 0);
	if (fd < 0) {
		pos = 0;
		pos = put(out, pos, "open(dir) failed\n");
		sys4(SYS_write, 1, (long)out, pos, 0);
		return;
	}
	pos = 0;
	pos = put(out, pos, "dir=");
	pos = put(out, pos, dir);
	pos = put(out, pos, " needle=");
	pos = put(out, pos, needle);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
	show_dirents(fd, 0, needle);	/* getdents64 (217) -> native body         */
	sys4(SYS_lseek, fd, 0, 0, 0);	/* rewind between the two interfaces       */
	show_dirents(fd, 1, needle);	/* getdents   (141) -> compat body         */
}
