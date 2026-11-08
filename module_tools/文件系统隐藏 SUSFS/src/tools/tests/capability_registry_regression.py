#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise production feature admission, init rollback and independent SKP routes.

Exact production functions are compiled against host lifecycle doubles. This is
not proof of hook reachability, kernel concurrency or installed-device behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from map_hook_regression import execute, execution_path, extract


PREAMBLE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "susfs_abi.h"
typedef uint32_t u32;
#define __init
#define __user
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define TWA_RESUME 0
#define THIS_MODULE NULL
#define SUSFS_LKM_VERSION "host-test"
#define SUSFS_LKM_MODULE_NAME "host-test"
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(v) (v)
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define set_bit(bit, map) ((map)[(bit) / 64] |= 1UL << ((bit) % 64))
#define clear_bit(bit, map) ((map)[(bit) / 64] &= ~(1UL << ((bit) % 64)))
#define test_bit(bit, map) (((map)[(bit) / 64] >> ((bit) % 64)) & 1UL)
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
static unsigned checks, exit_count, exit_order[32], active_allocations, queued;
static unsigned module_refs, test_uid, grouped_routes[6], prepares[6], lock_depth;
static bool fail_alloc, path_ready = true, syms_ready = true, redirect_ready = true;
static bool spoof_exiting;
static void grace_period(void) {}
static void (*spoof_sync_readers_fn)(void) = grace_period;
static void expect(bool ok, const char *message) {
 checks++;
 if (!ok) { fprintf(stderr, "FAIL check=%u: %s\n", checks, message); exit(1); }
}
static void discard_log(const char *fmt, ...) { (void)fmt; }
#define SUSFS_LOGI discard_log
#define pr_warn discard_log
#define pr_err discard_log
#define pr_info discard_log
#define pr_warn_ratelimited discard_log
static void *kzalloc(size_t n, int flags) {
 (void)flags; if (fail_alloc) return NULL;
 void *p = calloc(1, n); if (p) active_allocations++; return p;
}
static void kfree(void *p) { if (p) { expect(active_allocations > 0, "allocation balance"); active_allocations--; free(p); } }
static int copy_to_user(void *dst, const void *src, size_t n) { memcpy(dst, src, n); return 0; }
static int copy_from_user(void *dst, const void *src, size_t n) { memcpy(dst, src, n); return 0; }
static long strscpy(char *dst, const char *src, size_t n) {
 size_t len = strlen(src); if (len >= n) len = n - 1; memcpy(dst, src, len); dst[len] = 0; return (long)len;
}
static bool sus_path_lsm_active(void) { return path_ready; }
static bool susfs_hide_syms_active(void) { return syms_ready; }
static bool susfs_or_entry_armed(void) { return redirect_ready; }
struct callback_head { void (*func)(struct callback_head *); };
struct pt_regs { uintptr_t regs[31], pc; };
struct kprobe { int unused; };
static struct callback_head *pending_callback;
static int try_module_get(void *module) { (void)module; module_refs++; return 1; }
static void module_put(void *module) { (void)module; expect(module_refs != 0, "module ref balance"); module_refs--; }
static int task_work_add(void *task, struct callback_head *cb, int flags) {
 (void)task; (void)flags; expect(!pending_callback, "one pending callback"); pending_callback = cb; queued++; return 0;
}
static void *current;
typedef struct { unsigned val; } kuid_t;
static kuid_t current_uid(void) { return (kuid_t){test_uid}; }
static unsigned calls[16];
static void action(unsigned i, void **arg) { calls[i]++; *(int *)*arg = 0; }
static void sus_path_supercall(unsigned int cmd, void **arg) { (void)cmd; action(0, arg); }
static void susfs_sus_map_supercall(void **arg) { action(1, arg); }
static void susfs_kstat_supercall(unsigned int cmd, void **arg) { (void)cmd; action(2, arg); }
static void susfs_uname_supercall(void **arg) { action(3, arg); }
static void susfs_enable_log_supercall(void **arg) { action(4, arg); }
static void susfs_avc_spoof_supercall(void **arg) { action(5, arg); }
static void susfs_spoof_cmdline_supercall(void **arg) { action(6, arg); }
static void susfs_open_redirect_supercall(void **arg) { action(7, arg); }
static void susfs_sus_mount_supercall(void **arg) { action(8, arg); }
static int susfs_imports_guard(void) { return 0; }
static int susfs_imports_crosscheck(void) { return 0; }
static int ksu_patch_memory_init(void) { return 0; }
static void ksu_init_symbol_resolver(void) {}
static void susfs_self_hide_nodes(void) {}
static void record_exit(unsigned index);
'''


ROUTE_DOUBLES = r'''
static void take_lock(void) { expect(lock_depth == 0, "route locking is balanced"); lock_depth++; }
static void drop_lock(void) { expect(lock_depth == 1, "route unlock has owner"); lock_depth--; }
static void susfs_kstat_group_write_begin(void) { take_lock(); }
static void susfs_kstat_group_write_end(void) { drop_lock(); }
static int susfs_kstat_group_prepare_locked(void) { prepares[2]++; grouped_routes[2] = 7; return 0; }
static void susfs_map_group_write_begin(void) { take_lock(); }
static void susfs_map_group_write_end(void) { drop_lock(); }
static int susfs_map_group_prepare_locked(void) { prepares[3]++; grouped_routes[3] = 1; return 0; }
static void susfs_open_redirect_group_write_begin(void) { take_lock(); }
static void susfs_open_redirect_group_write_end(void) { drop_lock(); }
static int susfs_open_redirect_group_prepare_locked(bool forward) {
 prepares[4]++; grouped_routes[4] |= forward ? 1U : 1U << 11; return 0;
}
static void susfs_mount_group_write_begin(void) { take_lock(); }
static void susfs_mount_group_write_end(void) { drop_lock(); }
static int susfs_mount_group_prepare_locked(void) { prepares[5]++; grouped_routes[5] = 1; return 0; }
'''


TESTS = r'''
static void record_exit(unsigned index) {
 expect(exit_count < ARRAY_SIZE(exit_order), "bounded teardown");
 expect(susfs_layers[index].feature < 0 ||
        !test_bit(susfs_layers[index].feature, susfs_available_features), "capability cleared before owner exit");
 exit_order[exit_count++] = index;
}
static void verify_list(void) {
 struct st_susfs_enabled_features info = {0}; void *arg = &info;
 susfs_show_enabled_features(&arg);
 expect(info.err == 0, "feature list available");
 expect(!strncmp(info.enabled_features, "SUSFS_LKM_MODULES\n", 18), "module marker retained");
 for (unsigned i = 0; i < ARRAY_SIZE(enabled_features); i++) {
  const struct feature_entry *e = &enabled_features[i];
  expect((strstr(info.enabled_features, e->name) != NULL) ==
         (e->feature < 0 || susfs_supercall_feature_available(e->feature)), "feature list matches admission registry");
 }
 expect(active_allocations == 0, "feature list releases buffer");
}
static void reset(void) {
 expect(active_allocations == 0 && module_refs == 0 && !pending_callback, "previous case completely released");
 memset(susfs_available_features, 0, sizeof(susfs_available_features));
 for (unsigned i = 0; i < ARRAY_SIZE(susfs_layers); i++) susfs_layers[i].armed = false;
 path_ready = syms_ready = redirect_ready = true; spoof_exiting = false; spoof_sync_readers_fn = grace_period;
 exit_count = queued = test_uid = 0; fail_layer = 0; fail_alloc = false;
 memset(prepares, 0, sizeof(prepares)); memset(grouped_routes, 0, sizeof(grouped_routes));
}
static void syscall_case(unsigned cmd, bool handled) {
 int payload = 126;
 struct pt_regs real = {0}, regs = {0};
 real.regs[0] = KSU_INSTALL_MAGIC1; real.regs[1] = SUSFS_MAGIC; real.regs[2] = cmd; real.regs[3] = (uintptr_t)&payload;
 regs.regs[0] = (uintptr_t)&real; regs.regs[30] = 0x100; regs.pc = 0x200;
 struct pt_regs before = regs; unsigned q = queued;
 expect(reboot_pre(NULL, &regs) == (int)handled, "reboot decision matches readiness");
 if (!handled) {
  expect(!memcmp(&before, &regs, sizeof(regs)) && payload == 126, "unsupported leaves registers and payload intact");
  expect(queued == q && module_refs == 0, "unsupported creates no task work");
 } else {
  expect(regs.pc == 0x100 && regs.regs[0] == 0 && queued == q + 1, "supported defers and returns zero");
  expect(module_refs == 1 && pending_callback != NULL, "queued work pins module");
  struct callback_head *cb = pending_callback; pending_callback = NULL; cb->func(cb);
  expect(payload == 0 && module_refs == 0 && active_allocations == 0, "actual dispatcher completes and releases");
 }
}
int main(void) {
 reset();
 expect(ARRAY_SIZE(susfs_layers) == 16, "SKP layer order retained");
 unsigned owners[SUSFS_FEAT_COUNT] = {0}, fatal = 0;
 for (unsigned i = 0; i < ARRAY_SIZE(susfs_layers); i++) {
  if (susfs_layers[i].feature >= 0) owners[susfs_layers[i].feature]++;
  if (susfs_layers[i].fatal) { fatal++; expect(!strcmp(susfs_layers[i].name, "sus_path") || !strcmp(susfs_layers[i].name, "supercall"), "fatal policy unchanged"); }
 }
 expect(fatal == 2, "only original fatal layers");
 for (unsigned i = 0; i < SUSFS_FEAT_COUNT; i++) expect(owners[i] == 1, "each capability has exactly one owner");
 expect(susfs_cmd_handled(CMD_SUSFS_SHOW_VERSION) && susfs_cmd_handled(CMD_SUSFS_SHOW_VARIANT) &&
        susfs_cmd_handled(CMD_SUSFS_SHOW_ENABLED_FEATURES), "diagnostics always available");
 expect(!susfs_cmd_handled(0x1234) && !susfs_cmd_handled(CMD_SUSFS_ADD_SUS_MOUNT), "unknown and deprecated remain unsupported");
 susfs_supercall_set_feature((enum susfs_feature)-1, true); susfs_supercall_set_feature(SUSFS_FEAT_COUNT, true);
 expect(!susfs_supercall_feature_available((enum susfs_feature)-1) && !susfs_supercall_feature_available(SUSFS_FEAT_COUNT), "invalid feature bounds safe");
 for (unsigned failed = 0; failed <= ARRAY_SIZE(susfs_layers); failed++) {
  reset(); fail_layer = (int)failed;
  bool fatal_failure = failed && susfs_layers[failed - 1].fatal;
  expect(susfs_init() == (fatal_failure ? -EIO : 0), "init preserves fatal versus optional behavior");
  for (unsigned i = 0; i < SUSFS_FEAT_COUNT; i++) {
   bool expected = !fatal_failure && (!failed || susfs_layers[failed - 1].feature != (int)i);
   expect(susfs_supercall_feature_available(i) == expected, "only completed feature init advertised");
  }
  verify_list();
  if (!fatal_failure) {
   for (unsigned cmd = CMD_SUSFS_ADD_SUS_PATH; cmd <= CMD_SUSFS_ADD_SUS_MAP; cmd++) {
    int f = susfs_cmd_feature(cmd); if (f < 0) continue;
    expect(susfs_cmd_handled(cmd) == susfs_supercall_feature_available(f), "every known command shares feature decision");
    syscall_case(cmd, susfs_cmd_handled(cmd));
   }
   susfs_layers_down((int)ARRAY_SIZE(susfs_layers) - 1);
  }
  for (unsigned i = 0; i < SUSFS_FEAT_COUNT; i++) expect(!susfs_supercall_feature_available(i), "teardown clears all capability bits");
  for (unsigned i = 1; i < exit_count; i++) expect(exit_order[i - 1] > exit_order[i], "reverse teardown preserved");
  unsigned exits = exit_count; susfs_layers_down((int)ARRAY_SIZE(susfs_layers) - 1); expect(exit_count == exits, "repeated teardown idempotent");
 }
 reset(); expect(!susfs_init(), "load for runtime prerequisite tests");
 path_ready = syms_ready = redirect_ready = false; spoof_sync_readers_fn = NULL;
 expect(!susfs_cmd_handled(CMD_SUSFS_ADD_SUS_PATH) && !susfs_cmd_handled(CMD_SUSFS_ADD_OPEN_REDIRECT) &&
        !susfs_cmd_handled(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG), "missing prerequisite rejects command despite successful empty init");
 expect(!susfs_supercall_feature_available(SUSFS_FEAT_HIDE_SYMS), "inactive symbol hiding omitted"); verify_list();
 expect(susfs_cmd_handled(CMD_SUSFS_SET_UNAME) && susfs_cmd_handled(CMD_SUSFS_ADD_SUS_MAP) &&
        susfs_cmd_handled(CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS), "lazy optional features remain available");
 spoof_sync_readers_fn = grace_period; spoof_exiting = true;
 expect(!susfs_cmd_handled(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG), "bootconfig shutdown prerequisite");
 fail_alloc = true; struct st_susfs_enabled_features info = {0}; void *arg = &info; susfs_show_enabled_features(&arg);
 expect(info.err == -ENOMEM && !info.enabled_features[0], "feature list OOM reports ABI error"); fail_alloc = false;
 susfs_layers_down((int)ARRAY_SIZE(susfs_layers) - 1);
 reset();
 const unsigned families[] = {SKP_SEQ_KSTAT, SKP_SEQ_MAP, SKP_SEQ_REDIRECT, SKP_SEQ_MOUNT};
 const enum susfs_feature features[] = {SUSFS_FEAT_SUS_KSTAT, SUSFS_FEAT_SUS_MAP, SUSFS_FEAT_OPEN_REDIRECT, SUSFS_FEAT_SUS_MOUNT};
 for (unsigned i = 0; i < ARRAY_SIZE(families); i++) {
  expect(!susfs_supercall_feature_available(features[i]), "simulated optional init failed");
  expect(skp_prepare_route(families[i]) == 0 && grouped_routes[families[i]] != 0 && prepares[families[i]] != 0, "SKP route preparation independently recovers");
  expect(!susfs_supercall_feature_available(features[i]), "group recovery does not claim global init completed");
 }
 expect(lock_depth == 0, "group locks balanced");
 printf("CAPABILITY_REGISTRY checks=%u optional_failures=14 fatal_failures=2 grouped_recovery=4 passed=true\n", checks);
 return 0;
}
'''


def enum(source: str, name: str) -> str:
    match = re.search(rf"^enum {name} \{{.*?^\}};", source, re.M | re.S)
    if not match:
        raise ValueError("missing enum " + name)
    return match.group()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=True)
    paths = ["kernel/susfs.h", "kernel/susfs_supercall.c", "kernel/susfs_main.c",
             "kernel/spoof_cmdline.c", "kernel/skp_policy_adapter.c", "kernel/skp_sequential.h"]
    sources = {path: (repo / path).read_text(encoding="utf-8") for path in paths}
    sc, main_source = sources[paths[1]], sources[paths[2]]
    table = re.search(r"^static struct \{\n.*?^\} susfs_layers\[\] = \{.*?^\};", main_source, re.M | re.S)
    if not table:
        raise ValueError("missing layer table")
    entries = re.findall(r'\{\s*"([^"]+)",\s*(\w+),\s*(\w+),\s*(?:true|false),\s*false,\s*[-\w]+\s*\}', table.group())
    if len(entries) != 16:
        raise ValueError("unexpected layer table shape")
    stubs = []
    for index, (_, init, exit_) in enumerate(entries):
        stubs.append(f"static int {init}(void) {{ return 0; }}")
        if exit_ != "NULL":
            stubs.append(f"static void {exit_}(void) {{ record_exit({index}); }}")
    functions = ["susfs_supercall_set_feature", "susfs_supercall_feature_available",
                 "susfs_show_enabled_features", "susfs_show_version", "susfs_show_variant",
                 "susfs_cmd_feature", "susfs_cmd_handled", "susfs_tw_func", "reboot_pre"]
    pieces = {name: extract(sc, name) for name in functions}
    text = PREAMBLE + enum(sources[paths[0]], "susfs_feature") + "\n"
    text += extract(sc, "susfs_tw", "struct") + "\n"
    text += extract(sources[paths[3]], "susfs_spoof_cmdline_ready") + "\n"
    text += "static DECLARE_BITMAP(susfs_available_features, SUSFS_FEAT_COUNT);\n"
    text += pieces[functions[0]] + "\n" + pieces[functions[1]] + "\n"
    text += extract(sc, "feature_entry", "struct") + "\n" + extract(sc, "enabled_features", "initializer") + "\n"
    text += "static struct st_susfs_enabled_features susfs_enabled_features_nomem;\n"
    text += "\n".join(pieces[name] for name in functions[2:]) + "\n"
    text += "\n".join(stubs) + "\n" + table.group() + "\nstatic int fail_layer;\n"
    text += extract(main_source, "susfs_layers_down") + "\n" + extract(main_source, "susfs_init") + "\n"
    text += enum(sources[paths[5]], "skp_sequential_family") + "\n" + ROUTE_DOUBLES
    text += extract(sources[paths[4]], "skp_prepare_route") + "\n" + TESTS
    generated = out / "capability-registry.c"
    generated.write_text(text, encoding="utf-8")
    receipt = {"kernel_execution": False, "sources": {p: hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths},
               "limits": "Exact production functions with typed host doubles; not whole kernel translation unit, concurrent kernel execution, hook reachability or device evidence.",
               "runs": [], "mutations": []}
    base = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", "-Wno-unused-function", "-Wno-unused-parameter", "-I", execution_path(repo / "kernel")]
    for name, flags in [("normal", ["-O2"]), ("sanitized", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = out / (name + ".bin")
        command = base + flags + [execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (out/(name + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
        (out/(name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": name, "command": command, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (out/(name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (out/(name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            record.update(exit=run.returncode, stdout=run.stdout, stderr=run.stderr,
                          passed=run.returncode == 0 and not run.stderr and "passed=true" in run.stdout)
        receipt["runs"].append(record)
    mutations = {
        "accept-uninitialised": ("!test_bit(feature, susfs_available_features)", "false"),
        "leave-stale-capability": ("susfs_supercall_set_feature(susfs_layers[i].feature, false);", "(void)0;"),
        "ignore-forward-prerequisite": ("return susfs_or_entry_armed();", "return true;"),
        "block-grouped-recovery": (" int result = 0;\n switch (family)", " int result = -ENODEV;\n if (!susfs_supercall_feature_available(SUSFS_FEAT_SUS_KSTAT)) return result;\n switch (family)"),
    }
    if all(r["passed"] for r in receipt["runs"]):
        for name, (old, new) in mutations.items():
            if text.count(old) != 1:
                raise ValueError("ambiguous mutation " + name)
            mutated = out / (name + ".c")
            mutated.write_text(text.replace(old, new), encoding="utf-8")
            binary = out / (name + ".bin")
            build = execute(base + ["-O2", execution_path(mutated), "-o", execution_path(binary)])
            run = execute([execution_path(binary)]) if not build.returncode else None
            receipt["mutations"].append({"name": name, "build_exit": build.returncode,
                                         "exit": run.returncode if run else None,
                                         "detected": run is not None and run.returncode != 0 and "FAIL" in run.stderr})
    receipt["passed"] = all(r["passed"] for r in receipt["runs"]) and len(receipt["mutations"]) == len(mutations) and all(r["detected"] for r in receipt["mutations"])
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
