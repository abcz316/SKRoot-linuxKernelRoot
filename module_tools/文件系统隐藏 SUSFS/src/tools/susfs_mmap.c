// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_mmap - mmap a file, touch it, then report what the kernel tells this very
 * process about that mapping: the pagemap entry of its first page, the
 * process-wide Rss from /proc/self/smaps_rollup, and whether the file is still
 * named in /proc/self/[maps|smaps].
 *
 * Why it has to be one process: /proc/self/pagemap and /proc/self/smaps_rollup
 * describe the *caller's* mm, and a shell cannot read a file without forking -
 * the child that runs dd/od gets its own mm, so an address the shell learned from
 * /proc/self/maps is not an address in that child.  This tool does the mapping,
 * the touching and both reads itself, which is what makes the numbers below
 * meaningful for a rule that hides the mapped file.
 *
 * Android refuses non-PIE executables and the DDK container has no bionic sysroot,
 * so this is freestanding: -nostdlib -static-pie with our own _start.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_mmap tools/susfs_mmap.c
 *
 * Usage:
 *
 *     susfs_mmap <path> [bytes]      # default: whole file
 */

typedef unsigned long u64;
typedef long s64;

#define SYS_openat    56
#define SYS_close     57
#define SYS_getdents64 61
#define SYS_lseek     62
#define SYS_read      63
#define SYS_write     64
#define SYS_pread64   67
#define SYS_readlinkat 78
#define SYS_exit      93
#define SYS_newfstatat 79
#define SYS_mmap      222

#define AT_FDCWD   (-100)
#define O_RDONLY   0
#define PROT_READ  0x1
#define MAP_PRIVATE 0x02
#define SEEK_END   2
#define SEEK_SET   0

#define PAGE 4096

static char out[4096];
static char fbuf[8192];

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

static u64 puthex(char *dst, u64 pos, u64 v)
{
	char tmp[20];
	int n = 0;

	dst[pos++] = '0';
	dst[pos++] = 'x';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		unsigned d = (unsigned)(v & 0xf);
		tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
		v >>= 4;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static u64 parse_num(const char *s)
{
	u64 v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (u64)(*s++ - '0');
	return v;
}

/* Read a small proc file in full (no libc): returns the byte count or -1. */
static long read_file(const char *path, char *buf, u64 cap)
{
	long fd, n;

	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0)
		return -1;
	n = sys6(SYS_read, fd, (long)buf, (long)(cap - 1), 0, 0, 0);
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return n;
}

static u64 pagemap_entry(u64 addr)
{
	u64 e = 0;
	long fd;

	fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/pagemap", O_RDONLY, 0, 0, 0);
	if (fd < 0)
		return 0;
	/* pread64(fd, &e, 8, page * 8) - skipped pages are simply not written by a
	 * walk that did not run, so a zero here can mean "absent" or "not shown to
	 * an unprivileged caller"; the module's walk_skipped counter is the real
	 * observable, this line is the second opinion. */
	sys6(SYS_pread64, fd, (long)&e, 8, (long)((addr / PAGE) * 8), 0, 0);
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	return e;
}

/* "Rss:" out of a seq_file dump.  Returns kB, or 0 when the line is absent. */
static u64 find_rss(const char *buf, long n)
{
	long i;

	for (i = 0; i + 4 < n; i++) {
		if (buf[i] != 'R' || buf[i + 1] != 's' || buf[i + 2] != 's' ||
		    buf[i + 3] != ':')
			continue;
		i += 4;
		while (i < n && (buf[i] == ' ' || buf[i] == '\t'))
			i++;
		return parse_num(&buf[i]);
	}
	return 0;
}

/* How many times `name` is still named in a listing (0 = hidden). */
static u64 count_name(const char *buf, long n, const char *name)
{
	u64 hits = 0;
	long i, k;
	u64 nl = 0;

	while (name[nl])
		nl++;
	for (i = 0; i + (long)nl <= n; i++) {
		for (k = 0; k < (long)nl; k++)
			if (buf[i + k] != name[k])
				break;
		if (k == (long)nl)
			hits++;
	}
	return hits;
}

static const char *basename_of(const char *p)
{
	const char *b = p;

	while (*p) {
		if (*p == '/')
			b = p + 1;
		p++;
	}
	return b;
}

/* ---- the maps line itself, and the numbers a real file would put in it ----
 *
 * The columns after the permission flags are "pgoff major:minor ino".  For an
 * open_redirect rule those last two numbers come from the file the redirection
 * really opened, while the NAME on the same line is the target's - so printing the
 * line verbatim is what makes the two comparable: a line whose name and numbers
 * come from different files is a contradiction no real file can produce.
 *
 * stat(2) is not part of open_redirect's disguise (upstream leaves dev/ino to
 * sus_kstat), so the target path's st_dev/st_ino are the real target values, i.e.
 * exactly what the maps line has to agree with.  st_dev as userspace sees it is
 * the kernel's ENCODED dev_t (cp_new_stat -> new_encode_dev), so major/minor have
 * to be decoded from it: major = enc >> 8, minor = (enc & 0xff) | ((enc >> 20) << 8)
 * - the same numbers the kernel prints as "%02x:%02x". */
static u64 hexval(char c)
{
	if (c >= '0' && c <= '9')
		return (u64)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (u64)(c - 'a' + 10);
	return (u64)(c - 'A' + 10);
}

/* lowercase hex, no prefix and no padding - the width the kernel's own %02x uses
 * for major and minor */
static u64 puthex2(char *dst, u64 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

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

/* `out` is a pointer parameter, so sizeof(out) here is 8, not the caller's 4096-byte buffer:
 * the bound that meant to stop at the end of the buffer stopped at byte 8 instead, which the
 * accumulated prefix always exceeds - the mapping line was never copied, and `found = 1` then
 * suppressed the "(the mapping is not listed)" answer too.  Take the capacity explicitly. */
static u64 emit_maps_line(char *out, u64 cap, u64 pos, u64 addr)
{
	long n = read_file("/proc/self/maps", fbuf, sizeof(fbuf));
	long i = 0;
	int found = 0;

	pos = put(out, pos, "maps_line=");
	if (n > 0) {
		while (i < n) {
			long j = i, k;
			u64 start = 0, end = 0;

			while (j < n && fbuf[j] != '\n')
				j++;
			k = i;
			while (k < j && fbuf[k] != '-')
				start = (start << 4) | hexval(fbuf[k++]);
			k++;
			while (k < j && fbuf[k] != ' ')
				end = (end << 4) | hexval(fbuf[k++]);
			if (addr >= start && addr < end) {
				for (k = i; k < j && pos + 1 < cap; k++)
					out[pos++] = fbuf[k];
				out[pos] = 0;
				found = 1;
				break;
			}
			i = j + 1;
		}
	}
	if (!found)
		pos = put(out, pos, "(the mapping is not listed)");
	out[pos++] = '\n';
	return pos;
}

static u64 emit_stat(char *out, u64 pos, const char *label, const char *path)
{
	unsigned char st[128];
	long r = sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)st, 0, 0, 0);
	u64 enc = 0, ino = 0, major, minor;
	int i;

	pos = put(out, pos, "stat_");
	pos = put(out, pos, label);
	pos = put(out, pos, "=");
	if (r < 0) {
		pos = put(out, pos, "(stat failed)");
	} else {
		/* st_dev at 0, st_ino at 8 - the first two fields of struct stat, which
		 * is all this needs; byte-wise for the same reason the dirent reader is */
		for (i = 7; i >= 0; i--)
			enc = (enc << 8) | (u64)st[i];
		for (i = 15; i >= 8; i--)
			ino = (ino << 8) | (u64)st[i];
		major = (enc >> 8) & 0xfff;
		minor = (enc & 0xff) | (((enc >> 20) & 0xfffff) << 8);
		pos = puthex2(out, pos, major);
		out[pos++] = ':';
		pos = puthex2(out, pos, minor);
		out[pos++] = ' ';
		pos = putnum(out, pos, ino);
	}
	out[pos++] = '\n';
	return pos;
}

/* /proc/self/map_files/<start>-<end> is a symlink per mapping, and resolving it
 * names the mapped file - which is how a mapping the maps listing had already
 * dropped is still located.  Count the entries, how many of them still NAME
 * the file this tool mapped, and how many answer ENOENT (the disguise). */
struct linux_dirent64_min {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static void check_map_files(const char *base, u64 *entries, u64 *named, u64 *enoent)
{
	char dbuf[4096], path[256], link[512];
	long fd, n;

	*entries = *named = *enoent = 0;
	fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/map_files", O_RDONLY, 0, 0, 0);
	if (fd < 0)
		return;

	while ((n = sys6(SYS_getdents64, fd, (long)dbuf, (long)sizeof(dbuf), 0, 0, 0)) > 0) {
		long off = 0;

		while (off < n) {
			struct linux_dirent64_min *d = (void *)(dbuf + off);
			u64 pos;
			long r;

			if (d->d_reclen < 20 || off + d->d_reclen > n)
				break;
			if (d->d_name[0] != '.') {
				pos = put(path, 0, "/proc/self/map_files/");
				pos = put(path, pos, d->d_name);
				path[pos] = 0;
				(*entries)++;
				r = sys6(SYS_readlinkat, AT_FDCWD, (long)path, (long)link,
					 (long)(sizeof(link) - 1), 0, 0);
				if (r < 0) {
					if (r == -2)	/* -ENOENT: the disguise */
						(*enoent)++;
				} else {
					link[r] = 0;
					if (count_name(link, r, base))
						(*named)++;
				}
			}
			off += d->d_reclen;
		}
	}
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
"	bl	mmap_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void mmap_main(long argc, char **argv);

void mmap_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/mapped";
	const char *base;
	u64 want = 0, size, i, pos = 0, sum = 0, rss, pm;
	long fd, n;
	char *map;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		want = parse_num(argv[2]);

	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0) {
		pos = put(out, pos, "open failed\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
		return;
	}
	size = (u64)sys6(SYS_lseek, fd, 0, SEEK_END, 0, 0, 0);
	sys6(SYS_lseek, fd, 0, SEEK_SET, 0, 0, 0);
	if (want && want < size)
		size = want;

	map = (char *)sys6(SYS_mmap, 0, (long)size, PROT_READ, MAP_PRIVATE, fd, 0);
	if ((long)map < 0) {
		pos = put(out, pos, "mmap failed\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
		return;
	}

	/* Fault every page in: the whole point is a resident file-backed mapping. */
	for (i = 0; i < size; i += PAGE)
		sum += (u64)(unsigned char)map[i];

	pm = pagemap_entry((u64)map);
	n = read_file("/proc/self/smaps_rollup", fbuf, sizeof(fbuf));
	rss = (n > 0) ? find_rss(fbuf, n) : 0;

	base = basename_of(path);
	pos = put(out, pos, "path=");
	pos = put(out, pos, path);
	pos = put(out, pos, "\naddr=");
	pos = puthex(out, pos, (u64)map);
	pos = put(out, pos, "\nsize=");
	pos = putnum(out, pos, size);
	pos = put(out, pos, "\ntouch_sum=");
	pos = putnum(out, pos, sum);
	pos = put(out, pos, "\npagemap_first=");
	pos = puthex(out, pos, pm);
	pos = put(out, pos, "\nrollup_rss_kb=");
	pos = putnum(out, pos, rss);
	pos = put(out, pos, "\n");

	n = read_file("/proc/self/maps", fbuf, sizeof(fbuf));
	pos = put(out, pos, "maps_name_hits=");
	pos = putnum(out, pos, (n > 0) ? count_name(fbuf, n, base) : 0);
	pos = put(out, pos, "\n");

	n = read_file("/proc/self/smaps", fbuf, sizeof(fbuf));
	pos = put(out, pos, "smaps_name_hits=");
	pos = putnum(out, pos, (n > 0) ? count_name(fbuf, n, base) : 0);
	pos = put(out, pos, "\n");

	{
		u64 entries, named, enoent;

		check_map_files(base, &entries, &named, &enoent);
		pos = put(out, pos, "map_files_entries=");
		pos = putnum(out, pos, entries);
		pos = put(out, pos, " map_files_named_target=");
		pos = putnum(out, pos, named);
		pos = put(out, pos, " map_files_enoent=");
		pos = putnum(out, pos, enoent);
		pos = put(out, pos, "\n");
	}

	pos = emit_maps_line(out, sizeof(out), pos, (u64)map);
	pos = emit_stat(out, pos, "mapped", path);
	if (argc > 3)		/* argv[2] is the optional mapping size */
		pos = emit_stat(out, pos, "argv3", argv[3]);

	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}
