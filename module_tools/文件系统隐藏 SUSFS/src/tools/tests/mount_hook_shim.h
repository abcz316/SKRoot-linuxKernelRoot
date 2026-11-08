/* SPDX-License-Identifier: GPL-2.0-only */
/* Production bodies are inserted without rewriting by mount_hook_regression.py. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <linux/stat.h>
#include "skp_full_objects.h"
typedef uint32_t u32;
typedef uint64_t u64;
#define U64_MAX UINT64_MAX
#define __user
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SUS_MOUNT_MNTID_LABEL "mnt_id:\t"
#define SUS_MOUNT_MNTID_LABEL_LEN 8
#define SUS_MOUNT_SHOW_N 3
#define pr_warn discard_log
#define pr_err discard_log
#define SUSFS_LOGI discard_log
static unsigned int checks;
static void expect(bool condition, const char *message)
{
    checks++;
    if (!condition) { fprintf(stderr, "FAIL %u %s\n", checks, message); exit(1); }
}
static void discard_log(const char *format, ...) { (void)format; }
struct test_lock { bool held; };
static struct test_lock sus_mount_group_lock, sus_mount_ctl_lock;
static void mutex_lock(struct test_lock *lock) { expect(!lock->held, "no recursive lock"); lock->held = true; }
static void mutex_unlock(struct test_lock *lock) { expect(lock->held, "unlock owned lock"); lock->held = false; }
typedef struct { int value; } atomic_t;
static void atomic_inc(atomic_t *counter) { counter->value++; }
struct dentry { struct dentry *d_parent; struct { const char *name; } d_name; };
struct file { struct { struct dentry *dentry; } f_path; };
struct seq_file { char *buf; size_t count, size; struct file *file; };
struct vfsmount { unsigned int token; };
struct mount { struct vfsmount mnt; int mnt_id; struct mount *mnt_parent; };
static struct mount *real_mount(struct vfsmount *m) { return (struct mount *)((char *)m - offsetof(struct mount, mnt)); }
struct pt_regs { unsigned long regs[31], pc; };
struct kprobe { const char *symbol_name; int (*pre_handler)(struct kprobe *, struct pt_regs *); void *addr; };
struct kretprobe_instance { _Alignas(max_align_t) unsigned char data[256]; };
struct kretprobe {
    struct kprobe kp;
    int (*entry_handler)(struct kretprobe_instance *, struct pt_regs *);
    int (*handler)(struct kretprobe_instance *, struct pt_regs *);
    size_t data_size; int maxactive;
};
struct st_susfs_hide_sus_mnts_for_non_su_procs { bool enabled; int err; };
static unsigned long regs_return_value(struct pt_regs *regs) { return regs->regs[0]; }
static bool susfs_ptr_plausible(const void *pointer) { return (uintptr_t)pointer >= 4096; }
static int scnprintf(char *buffer, size_t capacity, const char *format, ...)
{
    va_list ap; va_start(ap, format); int result = vsnprintf(buffer, capacity, format, ap); va_end(ap);
    return result < 0 ? result : (size_t)result >= capacity ? (int)capacity - 1 : result;
}
/* PRODUCTION_STRUCTURES_AND_PROBES */
static bool mount_registered, mount_legacy_enabled;
static bool kr_fdinfo_ok, kr_statx_ok, kr_statx_do_ok, kr_mount_parent_ok;
static bool kp_sb_down_ok, kr_clone_ns_ok, kr_newmnt_ok;
static bool sus_mount_show_armed[SUS_MOUNT_SHOW_N];
static int n_show_probes;
static struct kprobe kp_sb_down = { .symbol_name = "generic_shutdown_super" };
static struct kretprobe kr_clone_ns = { .kp.symbol_name = "copy_mnt_ns" };
static struct kretprobe kr_newmnt = { .kp.symbol_name = "attach_recursive_mnt" };
static atomic_t n_fdinfo_entry, n_fdinfo_nolabel, n_fdinfo_hits, n_fdinfo_rewrites;
static atomic_t n_statx_entry, n_statx_ret, n_statx_err, n_statx_nobuf, n_statx_copyfail;
static atomic_t n_statx_nomap, n_statx_hits, n_statx_rewrites, n_ident_hits;
static atomic_t n_keep_rescans;
static unsigned int fail_show, fail_ret, registrations, unregistrations, copies, writes;
static unsigned int query_calls, global_calls, learned, dropped, commands, scans;
static bool fail_fdinfo, group_active, su_domain, ours = true, copy_fail;
static enum skp_object_query_mode mode = SKP_OBJECT_GROUPED;
static struct skp_mount_query_result result;
static u64 last_cookie, last_id, last_parent;
static int scan_result;
static enum skp_object_query_mode skp_policy_mount_query(u64 cookie, u64 id, u64 parent,
                                                       struct skp_mount_query_result *answer)
{
    query_calls++; last_cookie = cookie; last_id = id; last_parent = parent;
    *answer = result; return mode;
}
static bool skp_policy_paths_active(void) { expect(sus_mount_group_lock.held, "ownership tested under outer guard"); return group_active; }
static bool skp_policy_mounts_active(void) { return mode == SKP_OBJECT_GROUPED; }
static bool sus_mount_is_su_domain(void) { global_calls++; return su_domain; }
static bool sus_mount_is_ours(struct mount *m) { (void)m; global_calls++; return ours; }
static void sus_mount_idmap_drop(int id) { (void)id; dropped++; }
static void sus_mount_note_id(struct mount *m) { (void)m; learned++; }
static int sus_mount_shown_for(int id) { global_calls++; return id == 20 ? 10 : 0; }
static size_t copy_from_user(void *to, const void *from, size_t size)
{
    copies++; if (copy_fail) return size; memcpy(to, from, size); return 0;
}
static size_t copy_to_user(void *to, const void *from, size_t size)
{
    writes++; if (copy_fail) return size; memcpy(to, from, size); return 0;
}
static int register_kprobe(struct kprobe *probe)
{
    unsigned int bit = !strcmp(probe->symbol_name, "show_vfsstat") ? 1 :
                       !strcmp(probe->symbol_name, "show_mountinfo") ? 2 :
                       !strcmp(probe->symbol_name, "show_vfsmnt") ? 4 : 0;
    expect(sus_mount_ctl_lock.held, "registration owns ctl lock");
    registrations++; probe->addr = probe;
    return fail_show & bit ? -EINVAL : 0;
}
static int register_kretprobe(struct kretprobe *probe)
{
    unsigned int bit = !strcmp(probe->kp.symbol_name, "show_mountinfo") ? 1 :
                       !strcmp(probe->kp.symbol_name, "__arm64_sys_statx") ? 2 :
                       !strcmp(probe->kp.symbol_name, "do_statx") ? 4 : 0;
    expect(sus_mount_ctl_lock.held, "return registration owns ctl lock");
    registrations++; probe->kp.addr = probe;
    return fail_ret & bit ? -EINVAL : 0;
}
static void susfs_kp_forget_addr(struct kprobe *probe) { probe->addr = NULL; }
static void susfs_krp_forget_addr(struct kretprobe *probe) { probe->kp.addr = NULL; }
static void unregister_kprobe(struct kprobe *probe) { expect(probe->addr != NULL, "only registered probe removed"); unregistrations++; }
static void unregister_kretprobe(struct kretprobe *probe) { expect(probe->kp.addr != NULL, "only registered return probe removed"); unregistrations++; }
static int sus_mount_fdinfo_arm(void) { kr_fdinfo_ok = !fail_fdinfo; return fail_fdinfo ? -ENOENT : 0; }
static void sus_mount_fdinfo_disarm(void) { kr_fdinfo_ok = false; }
static int sus_mount_keep_command_locked(const char *value, bool bare)
{
    (void)value; (void)bare; expect(sus_mount_group_lock.held, "prefix and scan one transaction"); commands++; return 0;
}
static int sus_mount_mark_ksu_mounts(void)
{
    expect(sus_mount_group_lock.held, "scan cannot invert path then mount guard"); scans++; return scan_result;
}
/* PRODUCTION_FUNCTIONS */

static struct dentry fdparent = { .d_name.name = "fdinfo" }, fdentry = { .d_parent = &fdparent };
static struct file fdfile = { .f_path.dentry = &fdentry };
static char buffer[512];
static struct seq_file seq = { buffer, 0, sizeof(buffer), &fdfile };
static bool matches(const char *value) { return seq.count == strlen(value) && !memcmp(buffer, value, seq.count); }
static void text(const char *value) { strcpy(buffer, value); seq.count = strlen(value); seq.size = sizeof(buffer); seq.file = &fdfile; }
static void append(const char *value) { memcpy(buffer + seq.count, value, strlen(value) + 1); seq.count += strlen(value); }
static void reset_answers(void)
{
    memset(&result, 0, sizeof(result)); mode = SKP_OBJECT_GROUPED;
    result.hidden = 1; result.shown_id = 10; result.parent_id = 1;
    query_calls = global_calls = learned = dropped = copies = writes = 0;
    copy_fail = su_domain = false; ours = true; mount_legacy_enabled = false;
}

int main(void)
{
    struct mount parent = { .mnt_id = 10 }, child = { .mnt_id = 20, .mnt_parent = &parent };
    struct pt_regs regs = { .regs = { [0] = (unsigned long)&seq, [1] = (unsigned long)&child.mnt, [30] = 1234 } };
    struct kretprobe_instance ri = {0};
    struct sus_mount_kretprobe_state *state = (void *)ri.data;
    struct statx stat = { .stx_mask = 0x1000, .stx_mnt_id = 20 };
    struct st_susfs_hide_sus_mnts_for_non_su_procs info = { .enabled = true };
    void *argument = &info;
    unsigned int i, count;
    reset_answers();
    for (i = 0; i < 3; ++i) {
        regs.regs[0] = (unsigned long)&seq; regs.pc = 0;
        expect(sus_mount_show_probes[i]->pre_handler(sus_mount_show_probes[i], &regs) == 1, "each mount table suppresses group selected object");
        expect(regs.pc == 1234 && regs.regs[0] == 0, "mount skip returns zero result");
    }
    expect(query_calls == 3 && !global_calls && !learned && !dropped, "group readers never use/mutate global mount registries");
    expect(last_cookie == (u64)(uintptr_t)&child.mnt && last_id == 20 && last_parent == 10, "actual mount object passed to snapshot query");
    result.hidden = 0; expect(!sus_mount_show_pre(&kp_mountinfo, &regs), "negative group answer authoritative");
    result.hidden = 1; result.uncertain = 1;
    expect(!sus_mount_show_pre(&kp_mountinfo, &regs) && !global_calls, "uncertain group topology passes native result without fallback");
    result.uncertain = 0;
    mode = SKP_OBJECT_UPSTREAM; expect(!sus_mount_show_pre(&kp_mountinfo, &regs), "armed probes preserve upstream logical default off");
    mount_legacy_enabled = true; su_domain = true;
    expect(!sus_mount_show_pre(&kp_mountinfo, &regs), "upstream su exemption preserved");
    su_domain = false; expect(sus_mount_show_pre(&kp_mountinfo, &regs) == 1 && learned == 1, "upstream hiding still uses original global route");
    mode = SKP_OBJECT_LEGACY_SUBJECT; result.legacy_allowed = 0; count = global_calls;
    expect(!sus_mount_show_pre(&kp_mountinfo, &regs) && global_calls == count, "legacy copied subject denial avoids new gate");
    result.legacy_allowed = 1; su_domain = true;
    expect(sus_mount_show_pre(&kp_mountinfo, &regs) == 1, "legacy copied subject answer replaces upstream gate");

    reset_answers(); regs.regs[0] = (unsigned long)&seq;
    text("11 10 oldline\n"); sus_mount_parent_entry(&ri, &regs); append("20 10 0:1 / /child rw\n");
    result.hidden = 0; /* entry above had hidden=true so no parent rewrite */
    regs.regs[0] = 0; sus_mount_parent_ret(&ri, &regs);
    expect(matches("11 10 oldline\n20 10 0:1 / /child rw\n"), "hidden/skip parent state never rewrites previous line");
    regs.regs[0] = (unsigned long)&seq; text("11 10 oldline\n");
    sus_mount_parent_entry(&ri, &regs); append("20 10 0:1 / /child rw\n");
    /* Simulated snapshot retirement does not invalidate the copied scalar result. */
    memset(&result, 0, sizeof(result)); regs.regs[0] = 0; sus_mount_parent_ret(&ri, &regs);
    expect(matches("11 10 oldline\n20 1 0:1 / /child rw\n"), "only current appended parent ID rewritten from entry snapshot");
    result.parent_id = 123456789; result.hidden = 0;
    regs.regs[0] = (unsigned long)&seq; text(""); sus_mount_parent_entry(&ri, &regs);
    append("20 10 tail\n"); seq.size = seq.count + 1; regs.regs[0] = 0; sus_mount_parent_ret(&ri, &regs);
    expect(matches("20 10 tail\n"), "parent expansion respects capacity");
    seq.size = sizeof(buffer); regs.regs[0] = (unsigned long)&seq; text("");
    sus_mount_parent_entry(&ri, &regs); append("21 10 unexpected identity\n"); regs.regs[0] = 0;
    sus_mount_parent_ret(&ri, &regs); expect(matches("21 10 unexpected identity\n"), "different printed object left native");
    regs.regs[0] = (unsigned long)&seq; text(""); sus_mount_parent_entry(&ri, &regs);
    append("20 10 tail\n"); regs.regs[0] = (unsigned long)-EIO; sus_mount_parent_ret(&ri, &regs);
    expect(matches("20 10 tail\n"), "failed show does not rewrite");

    reset_answers(); state->ubuf = (unsigned long)&stat; state->requested_mask = 0; regs.regs[0] = 0;
    sus_mount_statx_ret(&ri, &regs); expect(stat.stx_mnt_id == 10 && query_calls == 1 && !global_calls, "statx group works with no legacy enables/entries");
    stat.stx_mnt_id = 20; result.uncertain = 1; sus_mount_statx_ret(&ri, &regs);
    expect(stat.stx_mnt_id == 20, "statx topology instability is native pass-through"); result.uncertain = 0;
    state->requested_mask = 0x4000; stat.stx_mnt_id = UINT64_C(0x100000014); count = copies;
    sus_mount_statx_ret(&ri, &regs); expect(stat.stx_mnt_id == UINT64_C(0x100000014) && copies == count, "requested UNIQUE namespace not read/reinterpreted");
    state->requested_mask = 0; stat.stx_mask = 0x4000; stat.stx_mnt_id = 20; count = query_calls;
    sus_mount_statx_ret(&ri, &regs); expect(stat.stx_mnt_id == 20 && query_calls == count, "returned UNIQUE mask also preserved");
    stat.stx_mask = 0x1000; stat.stx_mnt_id = UINT64_C(0x100000014);
    sus_mount_statx_ret(&ri, &regs); expect(stat.stx_mnt_id == UINT64_C(0x100000014) && query_calls == count, "u64 ordinary ID cannot wrap into int match");
    stat.stx_mnt_id = 20; copy_fail = true; sus_mount_statx_ret(&ri, &regs);
    expect(stat.stx_mnt_id == 20 && query_calls == count, "failed userspace read never queries partial key"); copy_fail = false;
    mode = SKP_OBJECT_UPSTREAM; mount_legacy_enabled = false; sus_mount_statx_ret(&ri, &regs);
    expect(stat.stx_mnt_id == 20, "statx upstream switch remains off after group arm");
    mount_legacy_enabled = true; sus_mount_statx_ret(&ri, &regs); expect(stat.stx_mnt_id == 10, "legacy statx translation retained");

    reset_answers(); mount_legacy_enabled = true;
    text("mnt_id:\t20\nino:\t80\n"); regs.regs[0] = (unsigned long)&seq;
    sus_mount_fdinfo_entry(&ri, &regs); append("mnt_id:\t20\nino:\t80\n"); regs.regs[0] = 0;
    sus_mount_fdinfo_ret(&ri, &regs);
    expect(matches("mnt_id:\t20\nino:\t80\nmnt_id:\t20\nino:\t80\n") && !global_calls, "group fdinfo owned solely by combined redirect route");
    mode = SKP_OBJECT_UPSTREAM; mount_legacy_enabled = true; sus_mount_fdinfo_ret(&ri, &regs);
    expect(matches("mnt_id:\t20\nino:\t80\nmnt_id:\t10\nino:\t80\n"), "legacy fdinfo modifies only current append interval");
    text("mnt_id:\t4294967316\nino:\t80\n"); state->start = 0;
    expect(!sus_mount_fdinfo_replace_mntid(&seq, 0), "oversized fdinfo decimal cannot narrow");
    text("junkmnt_id:\t20\n"); expect(!sus_mount_fdinfo_replace_mntid(&seq, 0), "label must start line");

    reset_answers(); group_active = false;
    susfs_mount_group_write_begin(); expect(!susfs_mount_group_prepare_locked(), "first grouped arm independent of global switch"); susfs_mount_group_write_end();
    expect(mount_registered && !mount_legacy_enabled && !scans, "group arm does not scan/renumber/enable legacy semantics");
    susfs_mount_group_write_begin(); sus_mount_keep_rescan(); susfs_mount_group_write_end();
    expect(!scans, "retained group probe ownership does not enable legacy prefix rescans");
    expect(susfs_mount_group_routes() == 127, "individual route status includes parent formatter");
    count = registrations; susfs_mount_group_write_begin(); susfs_mount_group_prepare_locked(); susfs_mount_group_write_end();
    expect(registrations == count, "repeat prepare does not double-register");
    group_active = true; commands = scans = 0;
    expect(sus_mount_keep_command("clear", false) == -EOPNOTSUPP && !commands, "legacy prefix cannot mutate active grouped config");
    info.enabled = false; susfs_sus_mount_supercall(&argument);
    expect(info.err == -EOPNOTSUPP && mount_registered, "legacy disable cannot tear down grouped probes");
    info.enabled = true; susfs_sus_mount_supercall(&argument);
    expect(info.err == -EOPNOTSUPP && !scans, "legacy enable cannot renumber grouped mounts");
    group_active = false; expect(!sus_mount_keep_command("reset", false) && commands == 1, "upstream prefix commands preserved");
    info.enabled = true; susfs_sus_mount_supercall(&argument);
    expect(!info.err && mount_legacy_enabled && scans == 1, "upstream enable scans exactly once under guard");
    info.enabled = false; susfs_sus_mount_supercall(&argument);
    expect(!info.err && !mount_legacy_enabled && !mount_registered, "upstream disable releases probes and logical switch");
    fail_show = 7; susfs_mount_group_write_begin(); expect(susfs_mount_group_prepare_locked() == -EINVAL, "zero table routes fail preparation"); susfs_mount_group_write_end();
    expect(!mount_registered && !susfs_mount_group_routes(), "failed arm cannot claim coverage");
    fail_show = 1; fail_ret = 7; fail_fdinfo = true;
    susfs_mount_group_write_begin(); expect(!susfs_mount_group_prepare_locked(), "partial upstream optional degradation preserved"); susfs_mount_group_write_end();
    expect(susfs_mount_group_routes() == 6, "partial route bits report unavailable parent/statx/fdinfo");
    sus_mount_unregister();
    printf("MOUNT_HOOK_REGRESSION checks=%u passed=true kernel_calls=false production_source=true\n", checks);
    return 0;
}
