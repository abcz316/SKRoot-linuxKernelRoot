// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_memrd - can another process' view of a hidden mapping still be read?
 *
 * sus_map hides a mapped file from /proc/<pid>/maps, /smaps, /smaps_rollup,
 * /pagemap and /map_files, but the CONTENT of that mapping has a second door:
 *
 *   /proc/<pid>/mem       -> mem_rw() -> access_remote_vm() -> __access_remote_vm()
 *   process_vm_readv(2)   -> process_vm_rw_single_vec() -> pin_user_pages_remote()
 *
 * Upstream SUSFS closes the first one (its __access_remote_vm hunk breaks the
 * transfer loop) and, measured from this kernel's mm/process_vm_access.c, does NOT
 * close the second - process_vm_readv never goes through __access_remote_vm.
 *
 * This tool reports both doors from the reading process' own point of view, so the
 * module's hook can be judged by what a caller actually gets:
 *
 *   direct_first  - read straight from the mapping (control: the owner always can)
 *   mem_read      - bytes returned by pread() on /proc/self/mem at that address
 *   mem_first     - the first bytes that came back (0 bytes -> nothing transferred)
 *   pvm_readv     - the return value of process_vm_readv() on the same range
 *   pvm_errno     - its errno when it failed (EFAULT is the expected refusal)
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie
 *         -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start
 *         -o susfs_memrd tools/susfs_memrd.c
 *
 * Usage: susfs_memrd <path> [len]
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;

#define SYS_exit      93
#define SYS_openat    56
#define SYS_close     57
#define SYS_read      63
#define SYS_write     64
#define SYS_pread64   67
#define SYS_lseek     62
#define SYS_mmap      222
#define SYS_process_vm_readv 270
#define SYS_getpid    172

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define PROT_READ 1
#define MAP_PRIVATE 2
#define PAGE 4096

/* struct iovec, and process_vm_readv's six arguments */
struct iovec {
	void *iov_base;
	u64 iov_len;
};

static char out[2048];
static char rd[4096];
static char direct[4096];
static struct iovec liov, riov;
static long pvm_rc = -1;

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;
	register long x8 __asm__("x8") = n;

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

static u64 puthex2(char *dst, u64 pos, unsigned v)
{
	static const char d[] = "0123456789abcdef";

	dst[pos++] = d[(v >> 4) & 0xf];
	dst[pos++] = d[v & 0xf];
	return pos;
}

static u64 parse_num(const char *s)
{
	u64 v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (u64)(*s++ - '0');
	return v;
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	memrd_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void memrd_main(long argc, char **argv);

void memrd_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/mapped";
	u64 len = 16, pos = 0, i, sum = 0, msum = 0;
	char *map;
	long fd, memfd, n, pid;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		len = parse_num(argv[2]);
	if (!len || len > PAGE)
		len = 16;

	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0) {
		pos = put(out, pos, "open failed\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
		return;
	}

	/* One page is enough: the question is whether THIS page can be read through
	 * /proc/self/mem, not how much of the file was mapped. */
	map = (char *)sys6(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
	if ((long)map < 0) {
		pos = put(out, pos, "mmap failed\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
		return;
	}
	for (i = 0; i < PAGE; i += 64)
		sum += (u64)(unsigned char)map[i];

	/* Control: the owner of the mapping reads it directly. */
	for (i = 0; i < len; i++)
		direct[i] = map[i];

	/* Door 1: /proc/self/mem at the mapping's address. */
	memfd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/mem", O_RDONLY, 0, 0, 0);
	if (memfd < 0) {
		pos = put(out, pos, "open(/proc/self/mem) failed\n");
	} else {
		n = sys6(SYS_pread64, memfd, (long)rd, (long)len, (long)map, 0, 0);
		sys6(SYS_close, memfd, 0, 0, 0, 0, 0);
		pos = put(out, pos, "mem_read=");
		pos = putnum(out, pos, n < 0 ? 0 : (u64)n);
		pos = put(out, pos, n < 0 ? " (error)" : "");
		pos = put(out, pos, " mem_sum=");
		if (n > 0) {
			for (i = 0; i < (u64)n; i++)
				msum += (u64)(unsigned char)rd[i];
		}
		pos = putnum(out, pos, msum);
		pos = put(out, pos, "\n");
	}

	/* Door 2: process_vm_readv on ourselves - the same address, another reader.
	 *
	 * The pid must be real: this kernel's process_vm_rw_core() calls
	 * find_get_task_by_vpid(pid) unconditionally (no "pid 0 means current"
	 * shortcut), so 0 answers -ESRCH - which is exactly what the first version of
	 * this tool measured in every state, rule or no rule. */
	liov.iov_base = rd;
	liov.iov_len = len;
	riov.iov_base = map;
	riov.iov_len = len;
	pid = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);
	n = sys6(SYS_process_vm_readv, pid, (long)&liov, 1, (long)&riov, 1, 0);
	pvm_rc = n;

	pos = put(out, pos, "path=");
	pos = put(out, pos, path);
	pos = put(out, pos, "\naddr=");
	pos = put(out, pos, "0x");
	{
		u64 a = (u64)map;
		char h[17];
		int k = 0;

		if (!a)
			h[k++] = '0';
		while (a) {
			h[k++] = "0123456789abcdef"[a & 0xf];
			a >>= 4;
		}
		while (k)
			out[pos++] = h[--k];
	}
	pos = put(out, pos, "\ndirect_first=");
	for (i = 0; i < len && i < 8; i++)
		pos = puthex2(out, pos, (unsigned)(unsigned char)direct[i]);
	pos = put(out, pos, "\ndirect_sum=");
	pos = putnum(out, pos, sum);
	pos = put(out, pos, "\npid=");
	pos = putnum(out, pos, (u64)pid);
	pos = put(out, pos, "\npvm_readv=");
	if (n < 0) {
		pos = put(out, pos, "errno=");
		pos = putnum(out, pos, (u64)(-n));
	} else {
		pos = putnum(out, pos, (u64)n);
	}
	pos = put(out, pos, "\n");
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}
