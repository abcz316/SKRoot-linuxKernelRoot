#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute extracted production path publication/matching with typed host doubles.

The extraction preserves function bodies byte-for-byte (apart from source newline
normalization). It fails closed if a requested declaration is missing or ambiguous.
This is a focused source regression, not a whole-TU/kernel/RCU/device test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


PREAMBLE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
typedef uint64_t u64;
typedef unsigned short umode_t;
typedef struct { unsigned int val; } kuid_t;
typedef struct { unsigned int value; } atomic_t;
#define NAME_MAX 255
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
struct inode_operations { unsigned int token; };
struct file_system_type { unsigned int token; };
struct super_block { u64 s_dev; struct file_system_type *s_type; };
struct inode { struct super_block *i_sb; u64 i_ino; umode_t i_mode; kuid_t i_uid; };
struct list_head { struct list_head *next, *prev; };
struct test_lock { bool held; };
static unsigned int checks;
static void expect(bool condition, const char *message)
{
    checks++;
    if (!condition) {
        fprintf(stderr, "FAIL check=%u: %s\n", checks, message);
        exit(1);
    }
}
static void INIT_LIST_HEAD(struct list_head *head) { head->next = head; head->prev = head; }
static void list_add_tail(struct list_head *node, struct list_head *head)
{
    node->prev = head->prev; node->next = head;
    head->prev->next = node; head->prev = node;
}
static void list_del(struct list_head *node)
{
    node->prev->next = node->next; node->next->prev = node->prev;
    INIT_LIST_HEAD(node);
}
#define list_for_each_entry(pos, head, member) \
    for (struct list_head *cursor = (head)->next; \
         cursor != (head) && \
         ((pos) = (struct sus_path_entry *)((char *)cursor - offsetof(struct sus_path_entry, member)), true); \
         cursor = cursor->next)
static void spin_lock(struct test_lock *lock) { expect(!lock->held, "spin lock is not recursive"); lock->held = true; }
static void spin_unlock(struct test_lock *lock) { expect(lock->held, "spin unlock owns lock"); lock->held = false; }
static void mutex_lock(struct test_lock *lock) { expect(!lock->held, "mutex is not recursive"); lock->held = true; }
static void mutex_unlock(struct test_lock *lock) { expect(lock->held, "mutex unlock owns lock"); lock->held = false; }
#define lockdep_assert_held(lock) expect((lock)->held, "production publisher holds lifecycle mutex")
static void atomic_inc(atomic_t *value) { value->value++; }
static void atomic_dec(atomic_t *value) { expect(value->value != 0, "pending counter cannot underflow"); value->value--; }
static long strscpy(char *destination, const char *source, size_t capacity)
{
    size_t length = strlen(source);
    if (length >= capacity) { memcpy(destination, source, capacity - 1); destination[capacity - 1] = 0; return -E2BIG; }
    memcpy(destination, source, length + 1); return (long)length;
}
'''

DOUBLES = r'''
static struct list_head sus_path_list;
static struct test_lock sus_path_lock, sus_path_lifecycle_lock;
static unsigned int sus_path_count;
static bool sus_path_stopping, sus_path_lifetime_watch;
static atomic_t sus_path_n_pending, n_identity_hits;
static int hide_from_apps = 1;
static char hide_name[NAME_MAX + 1];
static bool group_active, group_hidden, resolver;
static unsigned int caller_uid, legacy_queries, watch_calls;
static int watch_result;
static bool legacy_override = true, legacy_applies = true;
static kuid_t current_uid(void) { kuid_t uid = { caller_uid }; return uid; }
static bool susfs_is_current_proc_umounted_app(void) { return caller_uid >= 10000; }
static bool sus_path_is_resolver(void) { return resolver; }
static bool susfs_directory_inode_hidden(struct inode *inode) { (void)inode; return false; }
static bool skp_policy_paths_active(void) { return group_active; }
/* These are integration-boundary verdict doubles, not a copied policy core.
 * Subject/core tests separately execute the real immutable snapshot evaluator. */
static bool skp_policy_override(bool *applies)
{
    legacy_queries++;
    if (group_active) { *applies = false; return true; }
    *applies = legacy_applies; return legacy_override;
}
static bool skp_policy_paths_inode_override(struct inode *inode, bool *hidden)
{
    expect(inode != NULL, "inode matching receives actual fixture inode");
    *hidden = group_hidden; return group_active;
}
static bool skp_policy_paths_dirent_override(u64 dev, u64 ino, const char *name, bool *hidden)
{
    expect(dev == 11, "dirent matching receives held directory filesystem");
    expect(ino && name, "dirent matching receives fixture identity");
    *hidden = group_hidden; return group_active;
}
static int susfs_sb_watch_add(struct super_block *sb)
{
    expect(sus_path_lifecycle_lock.held && !sus_path_lock.held,
           "lifetime watch is outside spin lock and inside lifecycle mutex");
    expect(sb != NULL, "lifetime watch has superblock"); watch_calls++; return watch_result;
}
'''

TESTS = r'''
static struct file_system_type fs_type = { 1 }, other_type = { 2 };
static struct super_block sb = { 11, &fs_type }, alias_sb = { 12, &fs_type }, unrelated_sb = { 13, &other_type };
static struct inode object = { &sb, 41, 0100640, { 0 } };
static struct inode alias = { &sb, 41, 0100640, { 0 } };
static struct inode alternate_mount = { &alias_sb, 41, 0100640, { 0 } };
static struct inode unrelated = { &unrelated_sb, 41, 0100640, { 0 } };
static void reset(void)
{
    expect(!sus_path_lock.held && !sus_path_lifecycle_lock.held, "previous scenario released both locks");
    INIT_LIST_HEAD(&sus_path_list); sus_path_count = 0;
    sus_path_stopping = false; sus_path_lifetime_watch = false;
    sus_path_n_pending.value = n_identity_hits.value = 0;
    caller_uid = 10101; group_active = group_hidden = resolver = false;
    legacy_override = legacy_applies = true; legacy_queries = watch_calls = 0; watch_result = 0;
    memset(hide_name, 0, sizeof(hide_name)); object.i_mode = 0100640;
}
static struct sus_path_entry entry(struct inode *inode, bool protect)
{
    struct sus_path_entry result = { 0 };
    result.inode = inode; result.self_protect = protect;
    if (inode) { result.sb = inode->i_sb; result.dev = inode->i_sb->s_dev; result.ino = inode->i_ino; }
    strcpy(result.name, "fixture"); strcpy(result.path, "/owned-fixture"); result.path_len = 14;
    return result;
}
static int publish(struct sus_path_entry *value, bool merge)
{
    int result;
    INIT_LIST_HEAD(&value->list); INIT_LIST_HEAD(&value->retiring_list);
    mutex_lock(&sus_path_lifecycle_lock);
    result = sus_path_publish_entry(value, merge);
    mutex_unlock(&sus_path_lifecycle_lock);
    return result;
}
static void test_upgrade_and_authoritative_negative(void)
{
    struct sus_path_entry ordinary, protection, attempted_downgrade;
    unsigned int queries;
    umode_t original_mode;
    reset(); ordinary = entry(&object, false); original_mode = object.i_mode;
    expect(publish(&ordinary, false) == 0, "ordinary fixture publishes in upstream mode");
    expect(!ordinary.self_protect && object.i_mode == original_mode, "ordinary registration cannot widen mode");
    expect(sus_path_inode_hidden(&object), "ordinary inode hides before grouped takeover");
    expect(sus_path_is_hidden(&sb, 41, "fixture"), "ordinary dirent hides before grouped takeover");
    group_active = true; group_hidden = false; strcpy(hide_name, "fixture"); queries = legacy_queries;
    expect(!sus_path_inode_hidden(&object), "group negative suppresses exact ordinary inode");
    expect(!sus_path_inode_hidden(&alias), "group negative suppresses ordinary dev/ino fallback");
    expect(!sus_path_is_hidden(&sb, 41, "fixture"), "group negative suppresses ordinary dirent and hide_name fallback");
    expect(legacy_queries == queries, "authoritative negative never evaluates ordinary fallback gate");
    protection = entry(&object, true);
    expect(publish(&protection, false) == 1, "global protection reuses existing ordinary entry");
    expect(sus_path_count == 1 && ordinary.self_protect, "duplicate publication upgrades original entry in place");
    expect(ordinary.orig_mode == original_mode && (object.i_mode & 0777) == 0777,
           "only global protection records/restores upstream relaxed mode");
    expect(sus_path_inode_hidden(&object), "global protection wins over negative grouped inode verdict");
    expect(sus_path_is_hidden(&sb, 41, "fixture"), "global protection wins over negative grouped dirent verdict");
    expect(sus_path_inode_hidden(&alias), "self-protection still matches alternate inode with same dev/ino");
    expect(sus_path_inode_hidden(&alternate_mount), "self-protection keeps same-filesystem-type mount identity");
    expect(!sus_path_inode_hidden(&unrelated), "self-protection does not match unrelated filesystem type");
    attempted_downgrade = entry(&object, false);
    expect(publish(&attempted_downgrade, false) == -EBUSY, "grouped mode refuses ordinary duplicate writes");
    expect(ordinary.self_protect && sus_path_count == 1, "refused write cannot downgrade global protection");
    caller_uid = 0;
    expect(!sus_path_inode_hidden(&object) && !sus_path_is_hidden(&sb, 41, "fixture"), "root retains global management visibility");
    caller_uid = 2000;
    expect(sus_path_inode_hidden(&object) && sus_path_is_hidden(&sb, 41, "fixture"), "global protection covers non-app non-root callers");
    group_active = false;
    expect(publish(&attempted_downgrade, false) == 1, "ordinary duplicate in upstream mode is accepted as duplicate");
    expect(ordinary.self_protect && sus_path_inode_hidden(&object), "ordinary duplicate never downgrades protection after takeover ends");
    mutex_lock(&sus_path_lifecycle_lock); spin_lock(&sus_path_lock);
    list_del(&ordinary.list); sus_path_count--; spin_unlock(&sus_path_lock);
    sus_path_restore_mode(&ordinary); mutex_unlock(&sus_path_lifecycle_lock);
    expect(object.i_mode == original_mode && ordinary.orig_mode == 0, "global removal restores original target mode exactly");
    expect(!sus_path_inode_hidden(&object), "inode matcher no longer finds removed entry");
    memset(hide_name, 0, sizeof(hide_name));
    expect(!sus_path_is_hidden(&sb, 41, "fixture"), "dirent matcher no longer finds removed entry");
}
static void test_empty_and_failures(void)
{
    struct sus_path_entry ordinary, pending, resolved;
    static const struct inode_operations original_iop = { 7 };
    reset(); group_active = true; group_hidden = true;
    expect(sus_path_inode_hidden(&object), "group positive works with zero legacy entries");
    expect(sus_path_is_hidden(&sb, 41, "fixture"), "group positive dirent works with zero legacy entries");
    expect(!sus_path_is_hidden(NULL, 41, "fixture"), "unknown directory filesystem cannot match grouped rules");
    group_hidden = false;
    expect(!sus_path_inode_hidden(&object), "empty legacy table respects group negative");
    reset(); ordinary = entry(&object, false); sus_path_lifetime_watch = true; watch_result = -ENOMEM;
    expect(publish(&ordinary, false) == -ENOMEM, "watch failure prevents publication");
    expect(watch_calls == 1 && sus_path_count == 0 && object.i_mode == 0100640, "failed watch leaves old table/mode unchanged");
    sus_path_lifetime_watch = false; sus_path_stopping = true;
    expect(publish(&ordinary, false) == -ESHUTDOWN && !sus_path_count, "stopped layer refuses publication");
    reset(); pending = entry(NULL, false);
    expect(publish(&pending, false) == 0 && sus_path_n_pending.value == 1, "pending entry accounts unresolved object");
    resolved = entry(&object, false); resolved.orig_iop = &original_iop;
    expect(publish(&resolved, true) == 1, "resolved rule merges into existing pending slot");
    expect(pending.inode == &object && pending.orig_iop == &original_iop,
           "pending merge transfers inode and original-operation restoration ownership together");
    expect(!resolved.inode && !resolved.orig_iop && !sus_path_n_pending.value && sus_path_count == 1,
           "merged temporary entry retains neither transferred responsibility");
}
int main(void)
{
    test_upgrade_and_authoritative_negative(); test_empty_and_failures();
    printf("PATH_HOOK_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n", checks);
    return 0;
}
'''


def extract(source: str, name: str, structure: bool = False) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = (rf"^struct\s+{name}\s*\{{" if structure else
               rf"^static\s+(?:inline\s+)?(?:bool|int|void)\s+{name}\s*\([^;{{}}]*\)\s*\{{")
    matches = list(re.finditer(pattern, masked, flags=re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production definition for {name}, got {len(matches)}")
    match = matches[0]
    start, cursor, depth = match.start(), masked.index("{", match.start()), 0
    for cursor in range(cursor, len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            end = cursor + 1
            if structure:
                if masked[end:end + 1] != ";":
                    raise ValueError(f"structure {name} lacks closing semicolon")
                end += 1
            return source[start:end]
    raise ValueError(f"unbalanced production definition {name}")


def execution_path(path: Path) -> str:
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + "/" + path.as_posix()[3:] if os.name == "nt" else str(path)


def execute(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run((["wsl", "--exec"] if os.name == "nt" else []) + command,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=90, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/sus_path.c"
    source = source_path.read_text(encoding="utf-8")
    names = ["sus_path_relax_mode", "sus_path_restore_mode", "sus_path_gate_uid_ok",
             "sus_path_gate_ok", "sus_path_entry_gate_inode", "sus_path_entry_gate_any",
             "sus_path_is_hidden", "sus_path_inode_hidden", "sus_path_publish_entry"]
    pieces = {"sus_path_entry": extract(source, "sus_path_entry", structure=True)}
    pieces.update({name: extract(source, name) for name in names})
    constants = []
    for name in ("SUS_PATH_MAX_ENTRIES", "SUS_PATH_LEN"):
        matches = re.findall(rf"^#define {name} [^\n]+", source, flags=re.M)
        if len(matches) != 1:
            raise ValueError(f"missing or ambiguous production constant {name}")
        constants += matches
    generated = evidence / "path-hook-regression-extracted.c"
    generated.write_text(PREAMBLE + "\n" + "\n".join(constants) + "\n" +
                         pieces["sus_path_entry"] + "\n" + DOUBLES + "\n" +
                         "\n\n".join(pieces[name] for name in names) + "\n" + TESTS,
                         encoding="utf-8")
    receipt = {"production_source": "kernel/sus_path.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(piece.encode()).hexdigest()
                                     for name, piece in pieces.items()},
               "limits": "Exact extracted functions with typed host doubles; not whole-TU, i_op, kernel concurrency or device proof.",
               "runs": []}
    for label, flags in [("strict", ["-O2"]),
                         ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("path-hook-regression-" + label + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"] + flags
        command += [execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"PATH_HOOK_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "path-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
