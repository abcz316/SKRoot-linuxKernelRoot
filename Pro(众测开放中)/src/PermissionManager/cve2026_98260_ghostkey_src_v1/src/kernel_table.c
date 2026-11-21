/*
 * kernel_table.c - 内核偏移表
 *
 * 偏移值来自 kernel_offsets.h 的变量（默认值在 kernel_offsets.c，
 * 可被 --config <sh> 里抽出的 JSON 覆盖）。
 * kernel_table_load() 负责把这些值填充一次结构体。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "kernel_table.h"
#include "kernel_offsets.h"

static struct kernel_offsets g_offsets;
static int g_offsets_loaded = 0;

/* 用 kernel_offsets.h 里写死的宏填充 g_offsets */
static void load_hardcoded(void)
{
    memset(&g_offsets, 0, sizeof(g_offsets));

    g_offsets.page_offset      = KO_PAGE_OFFSET;
    g_offsets.timer_link       = KO_TIMER_LINK;
    g_offsets.cred_link        = KO_CRED_LINK;
    g_offsets.selinux_link     = KO_SELINUX_LINK;
    g_offsets.user_ns          = KO_USER_NS;
    g_offsets.root_user        = KO_ROOT_USER;
    g_offsets.groups           = KO_GROUPS;
    g_offsets.ucounts          = KO_UCOUNTS;

    g_offsets.task_cred        = KO_TASK_CRED;
    g_offsets.task_struct_size = KO_TASK_STRUCT_SIZE;
    g_offsets.cred_uid         = KO_CRED_UID;
    g_offsets.kitimer_node     = KO_KITIMER_NODE;
    g_offsets.kitimer_size     = KO_KITIMER_SIZE;
    g_offsets.task_alloc_link  = KO_TASK_ALLOC_LINK;

    g_offsets.cred_size        = KO_CRED_SIZE;
    g_offsets.cred_cap_inh     = KO_CRED_CAP_INH;
    g_offsets.cred_cap_perm    = KO_CRED_CAP_PERM;
    g_offsets.cred_cap_eff     = KO_CRED_CAP_EFF;
    g_offsets.cred_cap_bset    = KO_CRED_CAP_BSET;
    g_offsets.cred_cap_amb     = KO_CRED_CAP_AMB;
    g_offsets.cred_off_security = KO_CRED_OFF_SECURITY;
    g_offsets.cred_off_user    = KO_CRED_OFF_USER;
    g_offsets.cred_off_user_ns = KO_CRED_OFF_USER_NS;
    g_offsets.cred_off_ucounts = KO_CRED_OFF_UCOUNTS;
    g_offsets.cred_off_groups  = KO_CRED_OFF_GROUPS;

    g_offsets_loaded = 1;
}

int kernel_table_load(void)
{
    load_hardcoded();
    fprintf(stdout, "[config] loaded kernel table (kernel_offsets)\n");
    return 0;
}

const struct kernel_offsets *kernel_table_get(void)
{
    if (!g_offsets_loaded)
        load_hardcoded();
    return &g_offsets;
}

void kernel_table_dump(void)
{
    const struct kernel_offsets *o = kernel_table_get();
    printf("[config] page_offset: 0x%llx\n", (unsigned long long)o->page_offset);
    printf("[config] timer_link: 0x%llx\n", (unsigned long long)o->timer_link);
    printf("[config] cred_link: 0x%llx\n", (unsigned long long)o->cred_link);
    printf("[config] selinux_link: 0x%llx\n", (unsigned long long)o->selinux_link);
    printf("[config] kitimer_size: 0x%llx\n", (unsigned long long)o->kitimer_size);
    printf("[config] task_alloc_link: 0x%llx\n", (unsigned long long)o->task_alloc_link);
    printf("[config] cred: size=%u caps=%u/%u/%u/%u/%u sec=%u user=%u ns=%u uc=%u grp=%u\n",
           o->cred_size, o->cred_cap_inh, o->cred_cap_perm, o->cred_cap_eff,
           o->cred_cap_bset, o->cred_cap_amb, o->cred_off_security,
           o->cred_off_user, o->cred_off_user_ns, o->cred_off_ucounts, o->cred_off_groups);
}

/*
 * 按需打印：只有设置环境变量 C98260_DUMP=1 时才打全量表，
 * 默认保持安静（避免每次分派刷屏）。
 */
void kernel_table_dump_if_requested(void)
{
    const char *v = getenv("C98260_DUMP");
    if (v && *v && strcmp(v, "0") != 0)
        kernel_table_dump();
}
