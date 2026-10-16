/*
 * CPU core pairing helpers (big-core / consumer-core).
 *
 * Scans the online CPUs, reads their max frequency from sysfs, then pairs
 * them up by frequency cluster so the caller can pick a main/consumer core.
 */

#include "cpu.h"

typedef struct {
  int cpu;
  long freq;
} cpu_freq_t;

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

int collect_cpu_pairs(cpu_pair_t *pairs, int max_pairs) {
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

  int npair = 0;

  if (nf >= 2) {
    qsort(freqs, nf, sizeof(freqs[0]), cmp_cpu_freq_desc);

    /* 按频率簇分组（同频），簇内两两配对，大核簇排最前 */
    for (int i = 0; i < nf && npair < max_pairs;) {
      int j = i;
      while (j < nf && freqs[j].freq == freqs[i].freq) {
        j++;
      }
      int cnt = j - i;
      for (int k = 0; k + 1 < cnt && npair < max_pairs; k += 2) {
        pairs[npair].main_core = freqs[i + k].cpu;
        pairs[npair].consumer_core = freqs[i + k + 1].cpu;
        pairs[npair].freq = freqs[i + k].freq;
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
  if (!have_default && npair < max_pairs) {
    pairs[npair].main_core = 0;
    pairs[npair].consumer_core = 1;
    pairs[npair].freq = -1;
    npair++;
  }

  return npair;
}
