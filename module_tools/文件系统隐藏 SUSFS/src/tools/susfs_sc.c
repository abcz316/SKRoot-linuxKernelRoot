// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_sc - minimal SUSFS supercall client, no libc.
 *
 * The module's supercall entry point is the KernelSU reboot ABI:
 *
 *     reboot(KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, payload)
 *
 * (see kernel/susfs_supercall.c: reboot_pre() checks regs[0] against
 * KSU_INSTALL_MAGIC1 and regs[1] against SUSFS_MAGIC -- the second magic is the
 * SUSFS one, not KernelSU's MAGIC2.)
 *
 * The prebuilt ksu_susfs tool covers most commands, but not
 * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS and not CMD_SUSFS_ADD_SUS_PATH_LOOP,
 * so those have to be sent by hand.  This is the hand: it writes the command
 * number and a caller-supplied payload (as hex) straight to the syscall.
 *
 * Android refuses non-PIE executables, and we have no bionic sysroot in the
 * build container, so this is freestanding: -nostdlib -static-pie with our own
 * _start and raw svc instructions.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_sc tools/susfs_sc.c
 *
 * Usage:
 *
 *     susfs_sc <cmd-hex> [payload-hex]
 *     susfs_sc 0x55561 0100000000000000      # hide_sus_mnts_for_non_su_procs 1
 *
 * Exit status: 0 on a successful syscall, the syscall's (negated) error
 * otherwise, 2 for a usage error.
 */

typedef unsigned long u64;
typedef long s64;

#define SYS_write 64
#define SYS_exit 93
#define SYS_reboot 142

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA

/* Large enough for the biggest payload struct in the ABI
 * (st_susfs_spoof_cmdline_or_bootconfig and st_susfs_enabled_features are 8196:
 * a 4096-byte buffer here made the kernel copy 4 KB past its end). */
#define PAYLOAD_MAX 8196

/* Every reply struct in kernel/susfs_abi.h ends with its `int err` as the LAST
 * field, and all twelve have sizeof - offsetof(err) == 4 (260/256, 376/372,
 * 136/132, 8/4, 520/516, 8196/8192, 20/16), so when the caller supplies the
 * whole struct as hex the err lives at len-4.  Reading it as
 * `*(unsigned long *)(payload + ((len - 8) & ~7))` - which this tool used to do -
 * rounds DOWN to an 8-byte boundary and therefore prints the four bytes BEFORE
 * err for every struct whose size is 4 mod 8, i.e. for most of them. */
#define ERR_SEED 126		/* ERR_CMD_NOT_SUPPORTED, like the C tool */

static char payload[PAYLOAD_MAX] __attribute__((aligned(16)));
static char out[256];

static long sys4(long n, long a, long b, long c, long d)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
			 : "memory", "cc");
	return x0;
}

static unsigned long slen(const char *s)
{
	unsigned long n = 0;

	while (s[n])
		n++;
	return n;
}

static void puts_len(const char *s, unsigned long n)
{
	sys4(SYS_write, 1, (long)s, (long)n, 0);
}

static void say(const char *s)
{
	puts_len(s, slen(s));
}

static void say_hex(unsigned long v)
{
	static const char d[] = "0123456789abcdef";
	char *p = out;
	int i;

	p[0] = '0';
	p[1] = 'x';
	p += 2;
	for (i = 60; i >= 0; i -= 4)
		*p++ = d[(v >> i) & 0xf];
	*p++ = '\n';
	puts_len(out, p - out);
}

static void say_dec(long v)
{
	char tmp[24];
	char *p = out;
	int n = 0;
	unsigned long u;

	if (v < 0) {
		*p++ = '-';
		u = (unsigned long)(-v);
	} else {
		u = (unsigned long)v;
	}
	if (!u) {
		tmp[n++] = '0';
	}
	while (u) {
		tmp[n++] = (char)('0' + (u % 10));
		u /= 10;
	}
	while (n)
		*p++ = tmp[--n];
	puts_len(out, p - out);
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Parses a hex string (optionally 0x-prefixed) into payload[]. */
static long parse_hex(const char *s, char *dst, long cap)
{
	long n = 0;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	while (s[0] && s[1] && n < cap) {
		int hi = hexval(s[0]);
		int lo = hexval(s[1]);

		if (hi < 0 || lo < 0)
			return -1;
		dst[n++] = (char)((hi << 4) | lo);
		s += 2;
	}
	if (s[0] == ' ' || s[0] == '\n')
		return n;
	if (s[0])
		return -1;
	return n;
}

static long parse_cmd(const char *s)
{
	long v = 0;
	int i;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	for (i = 0; s[i]; i++) {
		int d = hexval(s[i]);

		if (d < 0)
			return -1;
		v = (v << 4) | d;
	}
	return v;
}

int sc_main(long argc, char **argv)
{
	long cmd, len;
	long rc;
	int err;

	if (argc < 2) {
		say("usage: susfs_sc <cmd-hex> [payload-hex]\n");
		return 2;
	}
	cmd = parse_cmd(argv[1]);
	if (cmd < 0) {
		say("susfs_sc: bad command number\n");
		return 2;
	}

	len = 0;
	if (argc > 2) {
		/* parse_hex() returns -1 when the input does not fit in the buffer, so
		 * an oversized struct is refused here instead of being handed to the
		 * kernel truncated (the kernel would copy_from_user the full struct and
		 * read past the end of this buffer). */
		len = parse_hex(argv[2], payload, PAYLOAD_MAX);
		if (len < 0) {
			say("susfs_sc: bad or oversized payload hex\n");
			return 2;
		}
	}

	/* Seed 126 like the stock C tool does: if the kernel does not recognise the
	 * command it leaves the buffer untouched, and "still 126" is how userspace
	 * detects "not supported".  Without the seed this client could never show
	 * that, which was the whole point of its err readback. */
	if (len >= 4)
		*(int *)(payload + len - 4) = ERR_SEED;

	say("susfs_sc: cmd ");
	say_hex((unsigned long)cmd);
	rc = sys4(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd,
		  (long)payload);
	say("susfs_sc: reboot() returned ");
	say_hex((unsigned long)rc);
	err = (len >= 4) ? *(int *)(payload + len - 4) : 0;
	say("susfs_sc: err=");
	say_dec(err);
	say(" (");
	say_hex((unsigned long)(long)err);
	say(")\n");
	if (len >= 4 && err == ERR_SEED)
		say("susfs_sc: err is still the 126 sentinel: this kernel did not answer that command\n");
	/* Non-zero when either half of the contract failed: the syscall result or
	 * the err the kernel wrote back. */
	return (rc == 0 && err == 0) ? 0 : 1;
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	sc_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);
