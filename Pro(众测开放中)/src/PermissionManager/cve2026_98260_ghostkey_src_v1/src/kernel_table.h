#ifndef KERNEL_TABLE_H
#define KERNEL_TABLE_H

#include <stdint.h>

struct kernel_offsets {
    char release[128];
    uint64_t timer_link;
    uint64_t cred_link;
    uint64_t selinux_link;
    uint64_t user_ns;
    uint64_t root_user;
    uint64_t groups;
    uint64_t ucounts;
    uint64_t page_offset;
    uint32_t task_cred;
    uint32_t task_struct_size;
    uint32_t cred_uid;
    uint32_t kitimer_node;
    uint64_t kitimer_size;
    /*
     * Return address of the kmem_cache_alloc_node() call that copy_process()
     * makes for the task_struct slab (i.e. copy_process + the instruction after
     * the BL). Tracepoint records carry this as their call_site, so matching on
     * it identifies the fork allocation without depending on the object size.
     * 0 = unknown (profiles written before blob v3); callers must fall back to
     * the size match in that case.
     */
    uint64_t task_alloc_link;
    /*
     * v4: forged-cred layout (struct cred offsets). Filled from the profile;
     * zero in v2/v3 blobs, in which case kernel_table.c substitutes the
     * android15-8 (6.6.x) defaults so old profiles behave exactly as before.
     * cred_size is sizeof(struct cred) (184 on 6.6/6.12/6.18, 176 on 5.15/6.1).
     */
    uint32_t cred_size;
    uint32_t cred_cap_inh;
    uint32_t cred_cap_perm;
    uint32_t cred_cap_eff;
    uint32_t cred_cap_bset;
    uint32_t cred_cap_amb;
    uint32_t cred_off_security;
    uint32_t cred_off_user;
    uint32_t cred_off_user_ns;
    uint32_t cred_off_ucounts;
    uint32_t cred_off_groups;
};

// Load the compile-time offsets from kernel_offsets.h
int kernel_table_load(void);

// Get loaded offsets
const struct kernel_offsets* kernel_table_get(void);

// Dump offsets for debugging
void kernel_table_dump(void);

// R4: dump only when C98260_DUMP is set (default: quiet, avoids 12 lines per dispatch)
void kernel_table_dump_if_requested(void);

#endif // KERNEL_TABLE_H
