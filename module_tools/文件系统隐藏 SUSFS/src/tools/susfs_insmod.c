// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_insmod - load susfs_guard_lkm.ko on a stock vendor kernel, without ksud.
 *
 * The problem
 * -----------
 * A vendor kernel's loader refuses this module for three reasons, and all three of
 * them live in the same place: the SHN_UNDEF branch of simplify_symbols().
 *
 *   1. unexported symbols (kallsyms_lookup_name, saved_boot_config, init_mm,
 *      task_work_add, ...) are not in the kernel's export table at all, so
 *      resolve_symbol() fails and the loader prints "Unknown symbol ... (err -22)";
 *   2. namespaced symbols (kern_path, ihold, override_creds, ...) additionally have
 *      to be imported by name - verify_namespace_is_imported() is the
 *      "VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver" refusal that a
 *      plain `insmod` hits;
 *   3. symbol CRCs (check_version()) and the Android KMI whitelist are checked
 *      there too.
 *
 * `case SHN_ABS:` does nothing but break (kernel/module.c, ~2342 in 5.15) and
 * relocation uses st_value verbatim for such a symbol.  So an undefined symbol that
 * has already been rewritten to st_shndx = SHN_ABS / st_value = <runtime address>
 * before the image reaches the kernel never enters any of those checks.  That is
 * exactly what ksud's userspace loader (SukiSU-Ultra userspace/ksuinit/src/lib.rs,
 * load_module()) does, and what this tool does:
 *
 *   1. map the .ko MAP_PRIVATE|PROT_WRITE (writes stay in this process' memory);
 *   2. walk .symtab: for every SHN_UNDEF entry with a non-empty name, look the name
 *      up in /proc/kallsyms and rewrite that Elf64_Sym in place to
 *      st_shndx = SHN_ABS, st_value = <address> (last kallsyms occurrence wins).
 *      Only the kernel's own symbols are eligible: a record followed by " [module]"
 *      is skipped whole, because its address belongs to another module's image, and
 *      the same name there can mean something unrelated to what we linked against;
 *   3. init_module(2) the patched buffer with the joined module parameters;
 *   4. if that fails and /dev/kmsg says the vermagic is wrong, patch the .modinfo
 *      "vermagic=" value in place and retry once.
 *
 * What it deliberately does NOT do
 * --------------------------------
 *   * no finit_module(2) (no fd, so no signature step at open), no KernelSU
 *     supercall, no /data/adb/ksu or ksud binary dependency;
 *   * no section is resized: the vermagic fixup keeps the .modinfo bytes exactly as
 *     long as they were.  The kernel's next_string() skips NUL padding, so a shorter
 *     required value is NUL-padded in place and a longer one is truncated - and
 *     that truncation is reported, never silent;
 *   * no address guessing: if /proc/kallsyms only prints zeroes (kptr_restrict),
 *     the load is refused rather than attempted with SHN_ABS/0 symbols;
 *   * no vermagic "fix" that the kernel did not ask for: the patch runs only after
 *     the kernel itself printed "version magic '...' should be '...'".
 *
 * Build (this is the recipe the CI tools job uses):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *         -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *         -o susfs_insmod tools/susfs_insmod.c
 *
 * Usage: susfs_insmod [-v] <module.ko> [module-params ...]
 * Exit:  0 on a successful load, else the failing syscall's errno (2 for usage).
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long s64;

/* The type a syscall number, argument and return value travels in: pointer-sized.
 * On the target it is plain `long`; a host build (SUSFS_INSMOD_HOSTTEST) must also
 * be able to hand a pointer through it, so it is spelled the compiler's way. */
typedef __INTPTR_TYPE__ sysarg;

/* -------------------------------------------------------------------------- *
 * syscalls (aarch64, asm-generic numbering)                                   *
 * -------------------------------------------------------------------------- */

#define SYS_exit	93
#define SYS_read	63
#define SYS_write	64
#define SYS_openat	56
#define SYS_close	57
#define SYS_lseek	62
#define SYS_mmap	222
#define SYS_init_module	105

#define AT_FDCWD	(-100)
#define O_RDONLY	0
#define O_WRONLY	1
#define O_NONBLOCK	0x800
#define SEEK_END	2
#define PROT_READ	1
#define PROT_WRITE	2
#define MAP_PRIVATE	2

/* The only host-dependent line in this file: the actual svc on the target, a shim
 * when the ELF/kallsyms/vermagic logic is exercised off-device
 * (-DSUSFS_INSMOD_HOSTTEST; nothing else is conditional except the _start block). */
#if defined(SUSFS_INSMOD_HOSTTEST)
extern sysarg sys6(sysarg n, sysarg a, sysarg b, sysarg c, sysarg d, sysarg e, sysarg f);
#else
static sysarg sys6(sysarg n, sysarg a, sysarg b, sysarg c, sysarg d, sysarg e, sysarg f)
{
	register sysarg x0 __asm__("x0") = a;
	register sysarg x1 __asm__("x1") = b;
	register sysarg x2 __asm__("x2") = c;
	register sysarg x3 __asm__("x3") = d;
	register sysarg x4 __asm__("x4") = e;
	register sysarg x5 __asm__("x5") = f;
	register sysarg x8 __asm__("x8") = n;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory", "cc");
	return x0;
}
#endif

/* -------------------------------------------------------------------------- *
 * output (one line at a time, so a failing load still prints its diagnostics)  *
 * -------------------------------------------------------------------------- */

#define OUT_MAX 8192
static char out_buf[OUT_MAX];
static u64 out_len;

static int verbose;

/* Defined below.  o_flush() must go through it instead of calling SYS_exit directly: a failed
 * stdout write (EPIPE - `susfs_insmod x.ko | head`, a reader that went away, a closed fd)
 * would otherwise leave /proc/sys/kernel/kptr_restrict at the 0 this tool wrote, i.e. kernel
 * addresses readable by every process on the device until the next reboot. */
static void finish(int code);

static void o_flush(void)
{
	if (!out_len)
		return;
	if (sys6(SYS_write, 1, (sysarg)out_buf, (sysarg)out_len, 0, 0, 0) < 0)
		finish(9);		/* EBADF: nowhere to talk to - restore, then exit */
	out_len = 0;
}

static void o_put(const char *s)
{
	if (out_len > OUT_MAX - 512)
		o_flush();
	while (*s && out_len < OUT_MAX)
		out_buf[out_len++] = *s++;
}

static void o_putn(const char *s, u64 n)
{
	u64 i;

	if (out_len > OUT_MAX - 512)
		o_flush();
	for (i = 0; i < n && out_len < OUT_MAX; i++)
		out_buf[out_len++] = s[i];
}

static void o_dec(u64 v)
{
	char tmp[24];
	int n = 0, i;

	if (v == 0) {
		if (out_len < OUT_MAX)
			out_buf[out_len++] = '0';
		return;
	}
	while (v) {
		tmp[n++] = (char)('0' + (int)(v % 10));
		v /= 10;
	}
	for (i = n - 1; i >= 0; i--)
		if (out_len < OUT_MAX)
			out_buf[out_len++] = tmp[i];
}

static void o_hex(u64 v)
{
	char tmp[17];
	int n = 0, i;

	if (v == 0) {
		o_put("0x0");
		return;
	}
	while (v) {
		tmp[n++] = "0123456789abcdef"[v & 0xf];
		v >>= 4;
	}
	o_put("0x");
	for (i = n - 1; i >= 0; i--)
		if (out_len < OUT_MAX)
			out_buf[out_len++] = tmp[i];
}

static void o_nl(void)
{
	if (out_len < OUT_MAX)
		out_buf[out_len++] = '\n';
	o_flush();
}

/* Every line this tool prints starts with this, so adb output is greppable. */
#define P "susfs_insmod: "

static const char *errname(long e)
{
	switch (e) {
	case 1: return "EPERM";
	case 2: return "ENOENT";
	case 7: return "E2BIG";
	case 8: return "ENOEXEC";
	case 9: return "EBADF";
	case 12: return "ENOMEM";
	case 13: return "EACCES";
	case 14: return "EFAULT";
	case 17: return "EEXIST";
	case 21: return "EISDIR";
	case 22: return "EINVAL";
	case 38: return "ENOSYS";
	case 89: return "ECANCELED";
	case 126: return "ENOKEY";
	case 129: return "EKEYREJECTED";
	default: return "";
	}
}

static int kptr_saved;
static char kptr_orig[16];
static u64 kptr_orig_len;

/* Put /proc/sys/kernel/kptr_restrict back the way we found it and exit. */
static void finish(int code)
{
	sysarg fd;

	if (kptr_saved) {
		fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/proc/sys/kernel/kptr_restrict",
			  O_WRONLY, 0, 0, 0);
		if (fd >= 0) {
			sys6(SYS_write, fd, (sysarg)kptr_orig, (sysarg)kptr_orig_len, 0, 0, 0);
			sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		}
		kptr_saved = 0;
	}
	sys6(SYS_exit, code, 0, 0, 0, 0, 0);
}

/* errno < 0 as returned by a syscall; err 0 means "no syscall involved". */
static void die(const char *msg, sysarg err)
{
	sysarg e = err < 0 ? -err : 0;

	o_put(P);
	o_put(msg);
	if (e) {
		o_put(": errno ");
		o_dec((u64)e);
		if (errname(e)[0]) {
			o_put(" (");
			o_put(errname(e));
			o_put(")");
		}
	}
	o_nl();
	finish((int)(e ? e : 1));
}

static void die2(const char *msg, const char *what, sysarg err)
{
	o_put(P);
	o_put(msg);
	if (what) {
		o_put(" '");
		o_put(what);
		o_put("'");
	}
	o_put(": errno ");
	o_dec((u64)(-err));
	if (errname(-err)[0]) {
		o_put(" (");
		o_put(errname(-err));
		o_put(")");
	}
	o_nl();
	finish((int)(-err));
}

/* -------------------------------------------------------------------------- *
 * tiny string helpers (no libc: the build is -nostdlib)                       *
 * -------------------------------------------------------------------------- */

static u64 s_len(const char *s)
{
	u64 n = 0;

	while (s[n])
		n++;
	return n;
}

static int s_eq_n(const char *a, const char *b, u64 n)
{
	u64 i;

	for (i = 0; i < n; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static void copy_n(char *dst, const char *src, u64 n)
{
	u64 i;

	for (i = 0; i < n; i++)
		dst[i] = src[i];
}

/* "haystack[0..hlen)" contains needle?  Returns the first offset or -1. */
static sysarg find_sub(const char *hay, u64 hlen, const char *needle, u64 nlen)
{
	u64 i;

	if (!nlen || hlen < nlen)
		return -1;
	for (i = 0; i + nlen <= hlen; i++) {
		if (hay[i] != needle[0])
			continue;
		if (s_eq_n(hay + i, needle, nlen))
			return (sysarg)i;
	}
	return -1;
}

/* -------------------------------------------------------------------------- *
 * ELF64 little-endian                                                     *
 * -------------------------------------------------------------------------- */

#define EI_CLASS	4
#define EI_DATA		5
#define ELFCLASS64	2
#define ELFDATA2LSB	1
#define EM_AARCH64	183

#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3

#define SHN_UNDEF	0
#define SHN_ABS		0xfff1

#define STB_WEAK	2

struct elf64_ehdr {
	u8  e_ident[16];
	u16 e_type;
	u16 e_machine;
	u32 e_version;
	u64 e_entry;
	u64 e_phoff;
	u64 e_shoff;
	u32 e_flags;
	u16 e_ehsize;
	u16 e_phentsize;
	u16 e_phnum;
	u16 e_shentsize;
	u16 e_shnum;
	u16 e_shstrndx;
};

struct elf64_shdr {
	u32 sh_name;
	u32 sh_type;
	u64 sh_flags;
	u64 sh_addr;
	u64 sh_offset;
	u64 sh_size;
	u32 sh_link;
	u32 sh_info;
	u64 sh_addralign;
	u64 sh_entsize;
};

struct elf64_sym {
	u32 st_name;
	u8  st_info;
	u8  st_other;
	u16 st_shndx;
	u64 st_value;
	u64 st_size;
};

/* Is this section's [sh_offset, sh_offset + sh_size) inside the mapped image?  Bounding the
 * offset first keeps `sh_offset + sh_size` from wrapping in u64 and reporting a section far
 * past the end of the file as "inside". */
static int sec_in_image(const struct elf64_shdr *s, u64 size)
{
	return s->sh_offset <= size && s->sh_size <= size - s->sh_offset;
}

/* The three layouts above are the ABI the kernel parses; a silent padding change
 * would move every field this tool writes, so fail the build instead. */
typedef char assert_ehdr_size[(sizeof(struct elf64_ehdr) == 64) ? 1 : -1];
typedef char assert_shdr_size[(sizeof(struct elf64_shdr) == 64) ? 1 : -1];
typedef char assert_sym_size[(sizeof(struct elf64_sym) == 24) ? 1 : -1];

/* -------------------------------------------------------------------------- *
 * kallsyms                                                                    *
 * -------------------------------------------------------------------------- */

/* How many undefined symbols this tool is willing to carry.  The module has ~100;
 * 4096 leaves room for a much bigger module and still fits in .bss. */
#define MAX_UNDEF 4096
#define MAX_LISTED 10

struct undef {
	const char *name;		/* into the mapped image (its string table) */
	struct elf64_sym *sym;		/* the entry to rewrite, also in the image */
	u32 len;
	u8 bind;
	u8 resolved;
};

static struct undef undefs[MAX_UNDEF];
static u32 nundef;

static u64 ks_lines;		/* usable "<addr> <type> <name>" records read */
static u64 ks_zero;		/* records whose address printed as 0 */
static u64 ks_addr;		/* records with a real address (any type) */
static u64 ks_dotted;		/* names with a '.' - not matchable by this tool */
static u64 ks_abs_type;		/* type a/A: absolute symbols, not addresses */
static u64 ks_module;		/* module symbols: another module's image, not the kernel's */

/* Save kptr_restrict and set it to 0, the way ksud does (it writes 1; root sees
 * real addresses at both values, the kernel's kallsyms_show_value() falls through
 * to the CAP_SYSLOG test).  Called before the first kallsyms read. */
static void kptr_relax(void)
{
	sysarg fd;
	sysarg n;

	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/proc/sys/kernel/kptr_restrict",
		  O_RDONLY, 0, 0, 0);
	if (fd < 0) {
		o_put(P "note: cannot read /proc/sys/kernel/kptr_restrict (errno ");
		o_dec((u64)(-fd));
		o_put(") - continuing, addresses will be checked\n");
		o_flush();
		return;
	}
	n = sys6(SYS_read, fd, (sysarg)kptr_orig, (sysarg)sizeof(kptr_orig) - 1, 0, 0, 0);
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	if (n <= 0) {
		o_put(P "note: /proc/sys/kernel/kptr_restrict is empty - continuing\n");
		o_flush();
		return;
	}
	kptr_orig_len = (u64)n;
	kptr_orig[n] = 0;
	kptr_saved = 1;

	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/proc/sys/kernel/kptr_restrict",
		  O_WRONLY, 0, 0, 0);
	if (fd < 0) {
		o_put(P "note: cannot write /proc/sys/kernel/kptr_restrict (errno ");
		o_dec((u64)(-fd));
		o_put(") - continuing without relaxing it\n");
		o_flush();
		return;
	}
	if (sys6(SYS_write, fd, (sysarg)"0", 1, 0, 0, 0) < 0) {
		o_put(P "note: writing 0 to kptr_restrict failed - continuing\n");
		o_flush();
	}
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);

	if (verbose) {
		o_put(P "kptr_restrict was \"");
		o_putn(kptr_orig, kptr_orig_len);
		while (kptr_orig_len && (kptr_orig[kptr_orig_len - 1] == '\n' ||
					 kptr_orig[kptr_orig_len - 1] == ' '))
			kptr_orig[--kptr_orig_len] = 0;
		o_put("\"; set to 0 for this run (restored on exit)\n");
		o_flush();
	}
}

/* One "<hex-address> <type> <name>" kallsyms line.  The type letter is the 2nd
 * field; 'a'/'A' means an absolute symbol whose printed value is NOT a runtime
 * address, so it is skipped.  A name containing '.' is skipped too: kallsyms is
 * full of compiler-generated names (.cold, .llvm.<hash>, $local aliases) and none
 * of them can be the undefined name of a linkable module symbol - matching is
 * exact, so a dotted undefined name would still match a dotted kallsyms name. */
static void ks_record(const char *s, u64 len, u32 *matched, u32 *zero_addr)
{
	u64 i = 0;
	u64 addr = 0;
	u64 nlen, j;
	u32 digits = 0;
	char type;

	while (i < len && (s[i] == ' ' || s[i] == '\t'))
		i++;
	for (; i < len; i++) {
		char c = s[i];
		u64 d;

		if (c >= '0' && c <= '9')
			d = (u64)(c - '0');
		else if (c >= 'a' && c <= 'f')
			d = (u64)(c - 'a') + 10;
		else if (c >= 'A' && c <= 'F')
			d = (u64)(c - 'A') + 10;
		else
			break;
		addr = (addr << 4) | d;
		digits++;
	}
	if (!digits || digits > 16 || i >= len || s[i] != ' ')
		return;			/* not a kallsyms record */

	while (i < len && s[i] == ' ')
		i++;
	if (i >= len)
		return;
	type = s[i++];
	while (i < len && s[i] == ' ')
		i++;
	if (i >= len)
		return;

	nlen = len - i;
	while (nlen && (s[i + nlen - 1] == ' ' || s[i + nlen - 1] == '\t' ||
			s[i + nlen - 1] == '\r'))
		nlen--;
	/* kallsyms prints its own symbols first and the module ones after them, and a module
	 * record carries a fourth field: " [module]".  That address lives in another module's
	 * image, so adopting it would resolve our import to a stranger's symbol - same name,
	 * unrelated meaning - and the load would succeed into the wrong thing instead of
	 * failing.  Only the kernel's symbols are ours to take, which is where ksud's walk
	 * ends too (it stops at the first module record). */
	for (j = 0; j < nlen; j++) {
		if (s[i + j] == ' ' || s[i + j] == '\t') {
			ks_module++;
			return;
		}
	}
	if (!nlen)
		return;

	ks_lines++;
	if (addr == 0) {
		ks_zero++;
		if (zero_addr)
			(*zero_addr)++;
		return;
	}
	if (!zero_addr && type != 'a' && type != 'A')
		ks_addr++;		/* real-address evidence, used for the kptr check */

	if (type == 'a' || type == 'A') {
		ks_abs_type++;
		return;
	}
	for (j = 0; j < nlen; j++) {
		if (s[i + j] == '.') {
			ks_dotted++;
			return;
		}
	}

	for (j = 0; j < nundef; j++) {
		struct undef *u = &undefs[j];

		if (u->len != nlen || u->name[0] != s[i])
			continue;
		if (!s_eq_n(u->name, s + i, nlen))
			continue;
		/* Last occurrence wins: a name may be defined more than once (a static
		 * inline that the compiler emitted in several TUs); the last one is the
		 * one a module link would have taken. */
		u->sym->st_shndx = SHN_ABS;
		u->sym->st_value = addr;
		u->resolved = 1;
		if (matched)
			(*matched)++;
	}
}

/* Stream /proc/kallsyms and rewrite the symbol entries as matches arrive.  The
 * file is ~10 MB on a GKI kernel, so it is read in chunks with a line assembler
 * instead of being slurped whole. */
static sysarg resolve_symbols(void)
{
	static char rbuf[65536];
	static char line[512];
	u64 llen = 0;
	sysarg fd, n;
	u64 i;
	u32 matched = 0;

	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/proc/kallsyms", O_RDONLY, 0, 0, 0);
	if (fd < 0)
		return fd;

	for (;;) {
		n = sys6(SYS_read, fd, (sysarg)rbuf, (sysarg)sizeof(rbuf), 0, 0, 0);
		if (n < 0) {
			sys6(SYS_close, fd, 0, 0, 0, 0, 0);
			return n;
		}
		if (n == 0)
			break;
		for (i = 0; i < (u64)n; i++) {
			char c = rbuf[i];

			if (c == '\n') {
				ks_record(line, llen, &matched, 0);
				llen = 0;
			} else if (llen < sizeof(line) - 1) {
				line[llen++] = c;
			} else {
				llen = 0;	/* absurdly long line: not a symbol */
			}
		}
	}
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	return (sysarg)matched;
}

/* -------------------------------------------------------------------------- *
 * kernel log (/dev/kmsg, /proc/kmsg)                                          *
 * -------------------------------------------------------------------------- */

#define KMSG_MAX 32768
static char kbuf[KMSG_MAX];
static u64 kbuf_len;

/* Open the record device *before* the load attempt: /proc/kmsg is a read-once
 * stream, and /dev/kmsg needs a seek to the end to mean "only new records". */
static sysarg kmsg_open(void)
{
	sysarg fd;

	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/dev/kmsg", O_RDONLY | O_NONBLOCK, 0, 0, 0);
	if (fd >= 0) {
		sys6(SYS_lseek, fd, 0, SEEK_END, 0, 0, 0);
		if (verbose) {
			o_put(P "kernel log: /dev/kmsg (seeked to end)\n");
			o_flush();
		}
		return fd;
	}
	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)"/proc/kmsg", O_RDONLY | O_NONBLOCK, 0, 0, 0);
	if (fd >= 0) {
		if (verbose) {
			o_put(P "kernel log: /proc/kmsg (unseekable, reading what is there)\n");
			o_flush();
		}
		return fd;
	}
	return fd;
}

static void kmsg_read_new(sysarg fd)
{
	sysarg n;

	kbuf_len = 0;
	if (fd < 0)
		return;
	for (;;) {
		n = sys6(SYS_read, fd, (sysarg)(kbuf + kbuf_len),
			 (sysarg)(KMSG_MAX - kbuf_len - 1), 0, 0, 0);
		if (n <= 0)
			break;		/* 0: no more records; <0: EAGAIN etc. */
		kbuf_len += (u64)n;
		if (kbuf_len >= KMSG_MAX - 1)
			break;
	}
	kbuf[kbuf_len] = 0;
}

static const char *const kmsg_interesting[] = {
	"Unknown symbol",
	"version magic",
	"does not import it",
	"disagrees about version",
	"no symbol version",
	"verification failed",
	"invalid module format",
	"module_layout",
};

static void kmsg_report(void)
{
	u64 pos = 0, shown = 0;

	if (!kbuf_len)
		return;
	while (pos < kbuf_len) {
		u64 end = pos;
		u64 len;
		u64 k;
		int keep = verbose;

		while (end < kbuf_len && kbuf[end] != '\n')
			end++;
		len = end - pos;
		if (len > 300)
			len = 300;
		for (k = 0; !keep && k < sizeof(kmsg_interesting) / sizeof(*kmsg_interesting); k++) {
			if (find_sub(kbuf + pos, len, kmsg_interesting[k],
				     s_len(kmsg_interesting[k])) >= 0)
				keep = 1;
		}
		if (keep && shown < 40) {
			o_put(P "  kmsg| ");
			o_putn(kbuf + pos, len);
			o_nl();
			shown++;
		}
		pos = end + 1;
	}
	if (!shown)
		o_put(P "kernel log: no load-related records in the new kmsg data\n");
}

/* The kernel's own message is
 *     <name>: version magic '<module magic>' should be '<kernel magic>'
 * and the value we must install is the second one.  Last occurrence wins. */
static const char *kmsg_required_vermagic(u64 *out_len)
{
	static const char pfx[] = "version magic '";
	static const char sep[] = "' should be '";
	const char *end = kbuf + kbuf_len;
	const char *p = kbuf;
	const char *hit = 0;
	sysarg off;

	while (p < end) {
		off = find_sub(p, (u64)(end - p), pfx, sizeof(pfx) - 1);
		if (off < 0)
			break;
		hit = p + off + (sizeof(pfx) - 1);
		p = hit;
	}
	if (!hit)
		return 0;

	off = find_sub(hit, (u64)(end - hit), sep, sizeof(sep) - 1);
	if (off < 0)
		return 0;
	hit += off + (sizeof(sep) - 1);

	off = find_sub(hit, (u64)(end - hit), "'", 1);
	if (off <= 0)
		return 0;
	*out_len = (u64)off;
	return hit;
}

/* -------------------------------------------------------------------------- *
 * .modinfo                                                                    *
 * -------------------------------------------------------------------------- */

/* Walk the NUL-separated entries the kernel's next_string() walks.  Returns the
 * value of "vermagic=" with its own (unterminated) length. */
static int modinfo_lookup(char *base, u64 size, const char *key, char **val, u64 *vlen)
{
	u64 klen = s_len(key);
	u64 pos = 0;

	while (pos < size) {
		u64 end = pos;
		u64 len;

		while (end < size && base[end])
			end++;
		len = end - pos;
		if (len > klen && s_eq_n(base + pos, key, klen) && base[pos + klen] == '=') {
			*val = base + pos + klen + 1;
			*vlen = len - klen - 1;
			return 0;
		}
		if (end >= size)
			break;
		pos = end + 1;		/* skip the NUL; empty entries are skipped too */
	}
	return -1;
}

/* -------------------------------------------------------------------------- *
 * main                                                                        *
 * -------------------------------------------------------------------------- */

static void usage(void)
{
	o_put(P "usage: susfs_insmod [-v] <module.ko> [module-params ...]\n");
	o_flush();
	finish(2);
}

void insmod_main(long argc, char **argv);

void insmod_main(long argc, char **argv)
{
	static char params[4096];
	static char modname[256];
	static char modpath[320];
	struct elf64_ehdr *eh;
	struct elf64_shdr *shdrs;
	struct elf64_shdr *symtab = 0;
	struct elf64_shdr *strtab = 0;
	struct elf64_shdr *modinfo = 0;
	const char *shstr = 0;
	u64 shstr_size = 0;
	const char *path;
	char *img;
	sysarg size, img_ret, fd, ret;
	sysarg kmsg_fd = -1;
	u64 plen = 0;
	u64 u, nsyms, i;
	u32 resolved = 0, unresolved = 0, unresolved_weak = 0, unresolved_hard = 0;
	u32 listed = 0, bad_sym = 0;
	int retried = 0;

	/* ---- argv ---- */
	u = 1;
	if (u < (u64)argc && argv[u][0] == '-' && argv[u][1] == 'v' && argv[u][2] == 0) {
		verbose = 1;
		u++;
	}
	if (u >= (u64)argc)
		usage();
	path = argv[u++];

	for (; u < (u64)argc; u++) {
		u64 alen = s_len(argv[u]);

		if (plen + (plen ? 1 : 0) + alen >= sizeof(params))
			die("module parameters too long (the kernel caps them at 4096 bytes)", -7);
		if (plen)
			params[plen++] = ' ';
		copy_n(params + plen, argv[u], alen);
		plen += alen;
	}
	params[plen] = 0;
	/* ---- map the module image read/write private ---- */
	fd = sys6(SYS_openat, AT_FDCWD, (sysarg)path, O_RDONLY, 0, 0, 0);
	if (fd < 0)
		die2("cannot open module", path, fd);
	size = sys6(SYS_lseek, fd, 0, SEEK_END, 0, 0, 0);
	if (size <= 0) {
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		if (size == 0)
			die2("module is empty", path, -22);
		die2("cannot size module (lseek)", path, size);
	}
	img_ret = sys6(SYS_mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	if (img_ret < 0)
		die2("cannot mmap module", path, img_ret);
	img = (char *)img_ret;

	o_put(P "image ");
	o_put(path);
	o_put(" (");
	o_dec((u64)size);
	o_put(" bytes)\n");
	o_flush();

	/* ---- ELF header + section table ---- */
	eh = (struct elf64_ehdr *)img;
	if (size < (sysarg)sizeof(*eh) || eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' ||
	    eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F')
		die2("not an ELF file", path, -8);
	if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB)
		die2("not ELF64 little-endian", path, -8);
	if (eh->e_machine != EM_AARCH64)
		die2("not an aarch64 module", path, -8);
	if (eh->e_shentsize != sizeof(struct elf64_shdr) || eh->e_shnum == 0 ||
	    eh->e_shoff == 0)
		die2("no usable section table", path, -8);
	/* Bound e_shoff first, then the table size: `e_shoff + shnum * 64 > size` wraps in u64 (a
	 * file with e_shoff = 2^64 - 64 and e_shnum = 1 passes it), and shdrs would then point
	 * outside the mapping - a read *and*, once the symbol table is rewritten, a write. */
	if (eh->e_shoff > (u64)size ||
	    (u64)eh->e_shnum > ((u64)size - eh->e_shoff) / sizeof(struct elf64_shdr))
		die2("section table outside the image", path, -8);
	shdrs = (struct elf64_shdr *)(img + eh->e_shoff);

	if (eh->e_shstrndx < eh->e_shnum) {
		struct elf64_shdr *s = &shdrs[eh->e_shstrndx];

		if (sec_in_image(s, (u64)size)) {
			shstr = img + s->sh_offset;
			shstr_size = s->sh_size;
		}
	}
	if (!shstr_size)
		die2("no section-name string table", path, -8);

	/* ---- locate .symtab (its sh_link is the string table) and .modinfo ---- */
	for (i = 0; i < eh->e_shnum; i++) {
		struct elf64_shdr *s = &shdrs[i];
		const char *name;

		if (s->sh_name >= shstr_size)
			continue;
		name = shstr + s->sh_name;
		if (s->sh_type == SHT_SYMTAB && !symtab)
			symtab = s;
		if (s->sh_type == SHT_PROGBITS && !modinfo && s_eq_n(name, ".modinfo", 9))
			modinfo = s;
	}
	if (!symtab)
		die2("no .symtab (stripped module?)", path, -8);
	if (symtab->sh_link >= eh->e_shnum)
		die2(".symtab has no string table (bad sh_link)", path, -8);
	strtab = &shdrs[symtab->sh_link];
	if (strtab->sh_type != SHT_STRTAB)
		die2(".symtab's sh_link is not a string table", path, -8);
	if (!sec_in_image(strtab, (u64)size) || !sec_in_image(symtab, (u64)size))
		die2("symbol table outside the image", path, -8);
	if (modinfo && !sec_in_image(modinfo, (u64)size))
		die2(".modinfo outside the image", path, -8);

	nsyms = symtab->sh_size / sizeof(struct elf64_sym);
	if (verbose) {
		o_put(P "ELF64 aarch64, ");
		o_dec(eh->e_shnum);
		o_put(" sections, .symtab holds ");
		o_dec(nsyms);
		o_put(" symbols (string table ");
		o_dec(strtab->sh_size);
		o_put(" bytes)\n");
		o_flush();
	}

	/* ---- collect the undefined symbols ---- */
	for (i = 1; i < nsyms; i++) {
		struct elf64_sym *sym = (struct elf64_sym *)(img + symtab->sh_offset) + i;
		const char *name;
		u64 nlen = 0;

		if (sym->st_shndx != SHN_UNDEF || sym->st_name == 0 ||
		    sym->st_name >= strtab->sh_size)
			continue;
		name = img + strtab->sh_offset + sym->st_name;
		while (nlen < strtab->sh_size - sym->st_name && name[nlen])
			nlen++;
		if (!nlen)
			continue;
		if (nundef >= MAX_UNDEF)
			die("too many undefined symbols for this tool", -7);
		undefs[nundef].name = name;
		undefs[nundef].sym = sym;
		undefs[nundef].len = (u32)nlen;
		undefs[nundef].bind = (u8)(sym->st_info >> 4);
		undefs[nundef].resolved = 0;
		/* A duplicate name in .symtab would resolve both entries through the
		 * same name lookup, so there is nothing to deduplicate here. */
		nundef++;
	}

	o_put(P "undefined symbols: ");
	o_dec(nundef);
	o_put("\n");
	o_flush();
	if (!nundef) {
		o_put(P "nothing to resolve; the kernel will look the symbols up itself\n");
		o_flush();
	}

	/* ---- rewrite them from /proc/kallsyms ---- */
	kptr_relax();
	if (nundef) {
		sysarg m = resolve_symbols();

		if (m < 0)
			die("cannot read /proc/kallsyms", m);
		if (!ks_lines)
			die("no symbol records parsed from /proc/kallsyms", -8);
		if (!ks_addr) {
			o_put(P "all ");
			o_dec(ks_zero);
			o_put(" kallsyms records printed a zero address (kptr_restrict); "
			      "refusing to load a module with zero addresses\n");
			o_flush();
			finish(13);	/* EACCES */
		}
		if (verbose) {
			o_put(P "kallsyms: ");
			o_dec(ks_lines);
			o_put(" records, ");
			o_dec(ks_addr);
			o_put(" with a real address, ");
			o_dec(ks_zero);
			o_put(" zero, ");
			o_dec(ks_abs_type);
			o_put(" absolute (a/A, skipped), ");
			o_dec(ks_dotted);
			o_put(" dotted names (skipped), ");
			o_dec(ks_module);
			o_put(" module symbols (skipped)\n");
			o_flush();
		}

		for (i = 0; i < nundef; i++) {
			if (!undefs[i].resolved) {
				bad_sym++;
				continue;
			}
			if (verbose) {
				o_put(P "  ");
				o_putn(undefs[i].name, undefs[i].len);
				o_put(" = ");
				o_hex(undefs[i].sym->st_value);
				o_put("  (SHN_ABS)\n");
				o_flush();
			}
		}
	}

	resolved = nundef - bad_sym;
	for (i = 0; i < nundef; i++) {
		if (undefs[i].resolved)
			continue;
		unresolved++;
		if (undefs[i].bind == STB_WEAK)
			unresolved_weak++;
		else
			unresolved_hard++;
	}

	o_put(P "resolved ");
	o_dec(resolved);
	o_put("/");
	o_dec(nundef);
	o_put("; unresolved ");
	o_dec(unresolved);
	if (unresolved) {
		o_put(" (");
		o_dec(unresolved_hard);
		o_put(" strong -> the load will fail with \"Unknown symbol\", ");
		o_dec(unresolved_weak);
		o_put(" weak -> tolerated by the kernel)");
	}
	o_put("\n");
	o_flush();

	if (unresolved) {
		o_put(P "unresolved names:");
		for (i = 0; i < nundef && listed < MAX_LISTED; i++) {
			if (undefs[i].resolved)
				continue;
			o_put(" ");
			o_putn(undefs[i].name, undefs[i].len);
			listed++;
		}
		if (unresolved > listed)
			o_put(" ...");
		o_put("\n");
		o_flush();
	}

	/* ---- module name, for the /sys/module check after the load ---- */
	{
		char *val;
		u64 vlen = 0;

		if (modinfo && modinfo_lookup(img + modinfo->sh_offset, modinfo->sh_size,
					      "name", &val, &vlen) == 0) {
			if (vlen >= sizeof(modname))
				vlen = sizeof(modname) - 1;
			copy_n(modname, val, vlen);
			modname[vlen] = 0;
		} else {
			/* fall back to the file's basename minus ".ko" */
			u64 n = 0, start = 0, l = s_len(path);

			for (i = 0; i < l; i++) {
				if (path[i] == '/')
					start = i + 1;
			}
			for (i = start; i < l && n < sizeof(modname) - 1; i++)
				modname[n++] = path[i];
			if (n > 3 && modname[n - 3] == '.' && modname[n - 2] == 'k' &&
			    modname[n - 1] == 'o')
				n -= 3;
			modname[n] = 0;
		}
	}

	/* ---- open the record device before the first attempt ---- */
	kmsg_fd = kmsg_open();
	if (kmsg_fd < 0) {
		o_put(P "note: no /dev/kmsg or /proc/kmsg (errno ");
		o_dec((u64)(-kmsg_fd));
		o_put(") - a failed load will not show the kernel's reason\n");
		o_flush();
	}

	/* init_module(2) ---- */
	o_put(P "init_module(");
	o_dec((u64)size);
	o_put(" bytes, ");
	o_dec(resolved);
	o_put(" symbols absolutized, params \"");
	o_put(params);
	o_put("\")\n");
	o_flush();

	/* param_values is NEVER NULL, not even with no parameters: load_module() calls
	 * strndup_user(uargs, ...) unconditionally (5.15 kernel/module.c:4046), and
	 * strndup_user(NULL) is -EFAULT.  ksud passes a CStr for the same reason.  The
	 * buffer below is static and always NUL-terminated, so "" is a valid argument. */
	ret = sys6(SYS_init_module, (sysarg)img, (sysarg)size,
		   (sysarg)params, 0, 0, 0);

	if (ret < 0) {
		u64 vlen = 0;
		const char *req;
		sysarg e = -ret;

		o_put(P "init_module failed: errno ");
		o_dec((u64)e);
		if (errname(e)[0]) {
			o_put(" (");
			o_put(errname(e));
			o_put(")");
		}
		o_put("\n");
		o_flush();
		if (resolved < nundef) {
			o_put(P "the kernel will report the names it could not resolve\n");
			o_flush();
		}
		kmsg_read_new(kmsg_fd);
		kmsg_report();

		req = kmsg_required_vermagic(&vlen);
		if (!req) {
			/* No vermagic complaint: do not invent one.  The kernel's own
			 * records above are the reason. */
			o_put(P "no \"version magic ... should be ...\" in the kernel log: "
			      "not patching the vermagic\n");
			o_flush();
			if (kmsg_fd >= 0)
				sys6(SYS_close, kmsg_fd, 0, 0, 0, 0, 0);
			finish((int)e);
		}

		{
			char *val = 0;
			u64 vlen_old = 0;
			u64 j;

			o_put(P "kernel requires vermagic \"");
			o_putn(req, vlen);
			o_put("\"\n");
			o_flush();

			if (!modinfo ||
			    modinfo_lookup(img + modinfo->sh_offset, modinfo->sh_size,
					   "vermagic", &val, &vlen_old) < 0 || !val) {
				o_put(P "no vermagic= entry in .modinfo: cannot patch it\n");
				o_flush();
				if (kmsg_fd >= 0)
					sys6(SYS_close, kmsg_fd, 0, 0, 0, 0, 0);
				finish((int)e);
			}

			o_put(P "vermagic slot is ");
			o_dec(vlen_old);
			o_put(" bytes, required value is ");
			o_dec(vlen);
			o_put(" bytes\n");
			o_flush();

			if (vlen <= vlen_old) {
				copy_n(val, req, vlen);
				for (j = vlen; j < vlen_old; j++)
					val[j] = 0;	/* next_string() skips NUL padding */
			} else {
				/* The value does not fit and the section must not grow.
				 * Keep the REQUIRED value's tail: with CONFIG_MODVERSIONS
				 * the kernel compares only the part after the first space
				 * (same_magic()), and the version prefix is exactly the
				 * part that legitimately differs between builds. */
				copy_n(val, req + (vlen - vlen_old), vlen_old);
				o_put(P "warning: required vermagic is longer than the slot; "
				      "truncated its head, kept the tail\n");
				o_flush();
			}

			o_put(P "patched .modinfo vermagic in place (");
			o_dec(vlen_old);
			o_put(" bytes, section length unchanged); retrying\n");
			o_flush();
		}

		retried = 1;
		ret = sys6(SYS_init_module, (sysarg)img, (sysarg)size,
			   (sysarg)params, 0, 0, 0);
		if (ret < 0) {
			sysarg e2 = -ret;

			o_put(P "init_module failed again after the vermagic fixup: errno ");
			o_dec((u64)e2);
			if (errname(e2)[0]) {
				o_put(" (");
				o_put(errname(e2));
				o_put(")");
			}
			o_put("\n");
			o_flush();
			kmsg_read_new(kmsg_fd);
			kmsg_report();
			if (kmsg_fd >= 0)
				sys6(SYS_close, kmsg_fd, 0, 0, 0, 0, 0);
			finish((int)e2);
		}
	}

	if (kmsg_fd >= 0)
		sys6(SYS_close, kmsg_fd, 0, 0, 0, 0, 0);

	/* ---- self-check: is the module there? ---- */
	{
		sysarg d;
		u64 n = 0;

		for (i = 0; i < sizeof("/sys/module/") - 1; i++)
			modpath[n++] = "/sys/module/"[i];
		for (i = 0; modname[i] && n < sizeof(modpath) - 1; i++)
			modpath[n++] = modname[i];
		modpath[n] = 0;

		o_put(P "loaded (vermagic fixup ");
		o_put(retried ? "used" : "not needed");
		o_put("); checking ");
		o_put(modpath);
		o_put("\n");
		o_flush();

		d = sys6(SYS_openat, AT_FDCWD, (sysarg)modpath, O_RDONLY, 0, 0, 0);
		if (d >= 0) {
			sys6(SYS_close, d, 0, 0, 0, 0, 0);
			o_put(P "OK: ");
			o_put(modpath);
			o_put(" exists\n");
		} else {
			o_put(P "WARNING: init_module returned 0 but ");
			o_put(modpath);
			o_put(" is not openable (errno ");
			o_dec((u64)(-d));
			o_put(")\n");
		}
		o_flush();
	}

	finish(0);
}

#if !defined(SUSFS_INSMOD_HOSTTEST)
__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	insmod_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);
#endif
