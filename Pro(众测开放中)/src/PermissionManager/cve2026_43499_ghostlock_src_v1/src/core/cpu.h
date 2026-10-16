#ifndef CPU_H
#define CPU_H

#include "common.h"

#define MAX_CPUS 256
#define MAX_PAIRS 256

typedef struct {
  int main_core;
  int consumer_core;
  long freq; /* main_core 的最大频率，读不到时为 -1 */
} cpu_pair_t;

/* 扫描在线 CPU、按频率排序配对，返回候选配对数量（含 0/1 兜底）。 */
int collect_cpu_pairs(cpu_pair_t *pairs, int max_pairs);

#endif
