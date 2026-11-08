#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the whole production directory-name helper against VFS doubles.

Only #include lines are removed from the production helper translation unit.
Actual getattr, permission, file_open and public dentry callbacks are extracted
from sus_path.c. Tests cover types, hardlinks, errors, alias references and rename
snapshots. They do not establish actual VFS, FUSE, CFI or device effects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from path_hook_regression import execute, execution_path


PREAMBLE = r'''
#define _DEFAULT_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#define noinline __attribute__((noinline))
#define __nocfi
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define WRITE_ONCE(x, value) __atomic_store_n(&(x), value, __ATOMIC_RELAXED)
#define DCACHE_DISCONNECTED (1U << 4)
struct dentry;
struct inode { unsigned int i_mode; struct dentry *alias; };
struct qstr { const unsigned char *name; unsigned int len; };
struct dentry {
    struct inode *inode;
    pthread_mutex_t d_lock;
    struct dentry *d_parent;
    unsigned int d_flags;
    struct qstr d_name;
    atomic_uint refs;
};
#define d_inode(alias) ((alias)->inode)
#define IS_ROOT(alias) ((alias)->d_parent == (alias))
static atomic_uint checks, lookups, releases, queries;
static bool available = true, supported = true, applies = true, present = true, manager;
static _Thread_local unsigned int held_lock;
static const char *selected = "bin.mt.plus";
static const struct dentry *contents_match;
static bool contents_active;
static const struct inode *search_match;
static bool skp_policy_path_contents_search_hidden(struct inode *inode)
{
 return contents_active && !manager && applies && supported && inode && inode == search_match;
}
static bool skp_policy_path_contents_present(void) { return contents_active; }
static bool skp_policy_path_contents_hidden(const struct dentry *dentry, bool include_self)
{
    (void)include_self;
    return contents_active && !manager && applies && supported && dentry && dentry == contents_match;
}
static void expect(bool ok, const char *message)
{
    atomic_fetch_add(&checks, 1);
    if (!ok) { fprintf(stderr, "FAIL %s\n", message); abort(); }
}
static void spin_lock(pthread_mutex_t *lock)
{
    expect(!held_lock, "no nested alias lock");
    expect(!pthread_mutex_lock(lock), "take alias lock");
    held_lock++;
}
static void spin_unlock(pthread_mutex_t *lock)
{
    expect(held_lock == 1, "own alias lock");
    held_lock--;
    expect(!pthread_mutex_unlock(lock), "release alias lock");
}
static struct dentry *fake_find_alias(struct inode *inode)
{
    expect(!held_lock, "lookup outside alias lock");
    atomic_fetch_add(&lookups, 1);
    if (inode->alias) atomic_fetch_add(&inode->alias->refs, 1);
    return inode->alias;
}
static unsigned long find_kernel_symbol_exact(const char *name)
{
    expect(!strcmp(name, "d_find_alias"), "resolve only expected builtin");
    return available ? (unsigned long)(uintptr_t)fake_find_alias : 0;
}
static void dput(struct dentry *alias)
{
    expect(!held_lock, "release alias outside lock");
    expect(atomic_fetch_sub(&alias->refs, 1) > 1, "release owned alias reference");
    atomic_fetch_add(&releases, 1);
}
static bool sus_path_group_supported(void) { return supported; }
static bool skp_policy_directory_names_present(void) { return present; }
static bool skp_policy_directory_name_hidden(const char *name)
{
    expect(!held_lock, "selector evaluated outside alias lock");
    atomic_fetch_add(&queries, 1);
    return applies && !manager && !strcmp(name, selected);
}
'''


INTEGRATION_DOUBLES = r'''
#define MAY_NOT_BLOCK 0x80
#define MAY_EXEC 0x01
#define MAY_WRITE 0x02
#define MAY_READ 0x04
#define MAY_ACCESS 0x10
#define MAY_OPEN 0x20
#define MAY_CHDIR 0x40
typedef atomic_uint atomic_t;
static atomic_t n_enoent_getattr, n_enoent_perm;
static void atomic_inc(atomic_t *value) { atomic_fetch_add(value, 1); }
struct path { struct dentry *dentry; };
struct file { struct path f_path; };
static bool resolver, exact_hidden;
static bool sus_path_is_resolver(void) { return resolver; }
static bool sus_path_inode_hidden(struct inode *inode)
{
    return !resolver && inode && (exact_hidden || susfs_directory_inode_hidden(inode));
}
static void ignore_inode_getattr(const struct path *p) { (void)p; }
static void ignore_inode_permission(struct inode *i, int m) { (void)i;(void)m; }
enum original_member { ORIG_inode_getattr, ORIG_inode_permission, ORIG_file_open, ORIG_inode_readlink, ORIG_inode_follow_link, ORIG_COUNT };
static unsigned int original_calls[ORIG_COUNT];
static int original_result[ORIG_COUNT];
static bool content_guarded, content_source;
static unsigned int consumed_guards, content_source_queries;
static bool content_consume_guard(struct file *file)
{
    expect(file != NULL, "file_open receives a real referenced file");
    consumed_guards++;
    return content_guarded;
}
static int content_original_file_open(struct file *file)
{
    expect(file != NULL, "shared original receives real file");
    original_calls[ORIG_file_open]++;
    return original_result[ORIG_file_open];
}
static bool skp_policy_content_source_applies(const struct path *path)
{
    expect(path != NULL, "content source receives path");
    content_source_queries++;
    return content_source;
}
/* The production macro calls its displaced original on 6.12. Keep its return
 * boundary while replacing the architecture-specific trampoline with a double. */
#define SUS_LSM_PASS_ORIG(hook, member, ...) do { ignore_##member(__VA_ARGS__); \
    original_calls[ORIG_##member]++; \
    return original_result[ORIG_##member]; \
} while (0)
'''


INTEGRATION_TESTS = r'''
static void integration_tests(void)
{
    struct inode inode = { .i_mode = S_IFREG | 0644 };
    struct dentry selected_alias = {
        .inode = &inode, .d_lock = PTHREAD_MUTEX_INITIALIZER,
        .d_parent = &parent, .d_name = { (const unsigned char *)"bin.mt.plus", 11 },
        .refs = ATOMIC_VAR_INIT(1),
    };
    struct dentry kept_alias = {
        .inode = &inode, .d_lock = PTHREAD_MUTEX_INITIALIZER,
        .d_parent = &parent, .d_name = { (const unsigned char *)"keep", 4 },
        .refs = ATOMIC_VAR_INIT(1),
    };
    struct path selected_path = { &selected_alias }, kept_path = { &kept_alias };
    struct file selected_file = { .f_path = { &selected_alias } };
    struct file kept_file = { .f_path = { &kept_alias } };
    applies = supported = present = true;
    manager = resolver = exact_hidden = false;
    selected = "bin.mt.plus";
    set_name("bin.mt.plus");
    memset(original_result, 0, sizeof(original_result));
    memset(original_calls, 0, sizeof(original_calls));

    expect(sus_path_inode_getattr(&selected_path) == -ENOENT, "actual getattr hides selected regular alias");
    expect(!original_calls[ORIG_inode_getattr], "hidden getattr does not call original");
    expect(!sus_path_inode_getattr(&kept_path), "actual getattr keeps other hardlink");
    expect(original_calls[ORIG_inode_getattr] == 1, "kept getattr reaches original");
    expect(content_file_open(&selected_file) == -ENOENT, "actual shared file_open hides selected regular alias");
    expect(original_calls[ORIG_file_open] == 1, "shared file_open preserves original check before name check");
    expect(!content_file_open(&kept_file), "actual shared file_open keeps other hardlink");
    expect(original_calls[ORIG_file_open] == 2, "kept shared file_open reaches original once");
    expect(consumed_guards == 2, "both shared opens preserve content guard handling");
    content_source = true;
    expect(content_file_open(&kept_file) == -EOPNOTSUPP, "shared unguarded content-source denial retained");
    content_guarded = true;
    expect(!content_file_open(&kept_file), "shared guarded content open retained");
    unsigned int source_before = content_source_queries;
    expect(content_file_open(&selected_file) == -ENOENT, "name hiding also covers guarded source open");
    expect(content_source_queries == source_before, "hidden source does not fall into content-source handling");
    content_source = content_guarded = false;
    expect(sus_path_dentry_hidden_public(&selected_alias), "public O_PATH dentry decision hides selected alias");
    expect(!sus_path_dentry_hidden_public(&kept_alias), "public O_PATH dentry decision keeps other hardlink");
    expect(!sus_path_dentry_hidden_public(NULL), "public O_PATH ignores absent dentry");
    expect(!sus_path_inode_permission(&inode, MAY_NOT_BLOCK), "regular permission never uses arbitrary alias or forces directory retry");
    expect(original_calls[ORIG_inode_permission] == 1, "regular permission reaches original");

    unsigned int before = atomic_load(&lookups);
    unsigned int original_before = original_calls[ORIG_inode_permission];
    expect(sus_path_inode_permission(&directory, MAY_NOT_BLOCK) == -ECHILD, "actual permission asks RCU directory walk to retry");
    expect(atomic_load(&lookups) == before, "RCU directory retry acquires no alias");
    expect(original_calls[ORIG_inode_permission] == original_before, "RCU retry does not call displaced original");
    expect(sus_path_inode_permission(&directory, 0) == -ENOENT, "ref-walk directory check hides matching alias");
    set_name("keep");
    original_result[ORIG_inode_permission] = -ECHILD;
    expect(sus_path_inode_permission(&directory, 0) == -ECHILD, "original permission ECHILD retained");
    present = false;
    original_result[ORIG_inode_permission] = -EACCES;
    expect(sus_path_inode_permission(&directory, MAY_NOT_BLOCK) == -EACCES, "no name rules preserves original permission without retry");
    present = true;
    original_result[ORIG_inode_getattr] = -EACCES;
    expect(sus_path_inode_getattr(&kept_path) == -EACCES, "original getattr EACCES retained");
    original_result[ORIG_file_open] = -EPERM;
    expect(content_file_open(&kept_file) == -EPERM, "original file_open EPERM retained");
    expect(content_file_open(&selected_file) == -EPERM, "original file_open denial preserved even for matching name");
    expect(sus_path_inode_getattr(NULL) == -EACCES, "empty path reaches original unchanged");

    original_result[ORIG_file_open] = 0;
    manager = true;
    expect(sus_path_inode_getattr(&selected_path) == -EACCES, "manager getattr exemption delegates original");
    expect(!content_file_open(&selected_file), "manager file_open exemption delegates original success");
    expect(!sus_path_dentry_hidden_public(&selected_alias), "manager public dentry remains visible");
    manager = false;
    applies = false;
    expect(sus_path_inode_getattr(&selected_path) == -EACCES, "selector exclusion retains original getattr");
    expect(!content_file_open(&selected_file), "selector exclusion retains original file_open success");
    applies = true;
    supported = false;
    expect(sus_path_inode_getattr(&selected_path) == -EACCES, "no-extra named getattr delegates original");
    expect(!content_file_open(&selected_file), "no-extra named file_open delegates original success");
    expect(!sus_path_dentry_hidden_public(&selected_alias), "no-extra public named dentry remains visible");
    supported = true;
    resolver = true;
    expect(sus_path_inode_getattr(&selected_path) == -EACCES, "resolving task is not blocked by named getattr");
    expect(!content_file_open(&selected_file), "resolving task is not blocked by named open");
    expect(!sus_path_dentry_hidden_public(&selected_alias), "resolving task public dentry remains visible");
    resolver = false;
    exact_hidden = true;
    expect(sus_path_inode_getattr(&kept_path) == -ENOENT, "exact legacy/grouped path hiding retained on unrelated name");
    expect(sus_path_dentry_hidden_public(&kept_alias), "public dentry retains exact path decision");
    expect(sus_path_inode_permission(&inode, 0) == -ENOENT, "ordinary inode permission retains exact path decision");
    exact_hidden = false;
    expect(atomic_load(&selected_alias.refs) == 1 && atomic_load(&kept_alias.refs) == 1,
           "integration callbacks do not retain regular alias references");
    /* The matcher boundary supplies ancestry verdicts; the separate sequential
     * suite executes that matcher with real rule tables and synthetic ancestry. */
    contents_active = true;contents_match = &kept_alias;present = false;
    original_result[ORIG_inode_getattr] = original_result[ORIG_inode_permission] = 0;
    original_result[ORIG_inode_readlink] = original_result[ORIG_inode_follow_link] = 0;
    expect(sus_path_inode_getattr(&kept_path) == -ENOENT, "content descendant getattr blocked");
    expect(content_file_open(&kept_file) == -ENOENT, "content descendant file open blocked");
    expect(sus_path_dentry_hidden_public(&kept_alias), "content descendant O_PATH blocked");
    expect(!sus_path_inode_getattr(&selected_path), "non-descendant anchor getattr allowed");
    expect(!content_file_open(&selected_file), "non-descendant anchor file open allowed");
    original_result[ORIG_inode_readlink] = -EPERM;
    original_result[ORIG_inode_follow_link] = -EACCES;
    manager = true;
    expect(!content_file_open(&kept_file), "manager can open content descendant");
    expect(!sus_path_dentry_hidden_public(&kept_alias), "manager O_PATH descendant visible");
    manager = false;resolver = true;
    expect(!content_file_open(&kept_file), "resolver can open content descendant");
    resolver = false; manager = false; present = false; search_match = &directory;
    original_result[ORIG_inode_permission] = 0;
    expect(sus_path_inode_permission(&directory, MAY_EXEC) == -ENOENT, "anchor search denies child traversal without new LSM hooks");
    expect(sus_path_inode_permission(&directory, MAY_EXEC | MAY_NOT_BLOCK) == -ENOENT, "RCU anchor search also denies child traversal");
    expect(!sus_path_inode_permission(&directory, MAY_READ | MAY_OPEN), "anchor remains openable");
    expect(!sus_path_inode_permission(&directory, MAY_EXEC | MAY_CHDIR), "anchor remains enterable");
    expect(!sus_path_inode_permission(&directory, MAY_EXEC | MAY_ACCESS), "anchor access check delegates original");
    expect(sus_path_inode_permission(&directory, MAY_EXEC | MAY_WRITE) == -ENOENT, "creating under anchor is denied");
    manager = true;
    expect(!sus_path_inode_permission(&directory, MAY_EXEC), "manager search exemption retained");
    manager = false; available = false;
    expect(susfs_directory_names_init() == -EOPNOTSUPP, "alias unavailable fixture");
    expect(sus_path_inode_permission(&directory, MAY_EXEC) == -ENOENT, "anchor search works without alias lookup");
    search_match = NULL; available = true; expect(!susfs_directory_names_init(), "restore alias fixture");
    resolver = false;contents_active = false;contents_match = NULL;present = true;

}
'''


TESTS = r'''
static char live_name[NAME_MAX + 1] = "bin.mt.plus";
static struct inode directory = { .i_mode = S_IFDIR | 0755 };
static struct dentry parent;
static struct dentry alias = {
    .inode = &directory, .d_lock = PTHREAD_MUTEX_INITIALIZER,
    .d_parent = &parent, .d_name = { (const unsigned char *)live_name, 11 },
    .refs = ATOMIC_VAR_INIT(1),
};
static void set_name(const char *value)
{
    size_t length = strlen(value);
    expect(length <= NAME_MAX, "test name fits");
    spin_lock(&alias.d_lock);
    memcpy(live_name, value, length + 1);
    alias.d_name.name = (const unsigned char *)live_name;
    alias.d_name.len = (unsigned int)length;
    spin_unlock(&alias.d_lock);
}
static void *rename_worker(void *unused)
{
    (void)unused;
    for (unsigned int i = 0; i < 5000; ++i)
        set_name((i & 1) ? "bin.mt.plus" : "unrelated");
    return NULL;
}
int main(void)
{
    directory.alias = &alias;
    expect(!susfs_directory_names_ready(), "uninitialized capability disabled");
    expect(!susfs_directory_inode_hidden(&directory), "no lookup while unavailable");
    available = false;
    expect(susfs_directory_names_init() == -EOPNOTSUPP, "missing builtin rejected");
    expect(!susfs_directory_names_ready(), "missing builtin leaves disabled");
    available = true;
    expect(!susfs_directory_names_init(), "builtin initializes capability");
    expect(susfs_directory_names_ready(), "capability becomes ready");

    expect(susfs_directory_entry_hidden("bin.mt.plus", 11, DT_DIR), "directory entry exact name");
    expect(susfs_directory_entry_hidden("bin.mt.plus", 11, DT_REG), "same-name regular file hidden");
    unsigned int before = atomic_load(&queries);
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_LNK), "same-name symlink remains");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_UNKNOWN), "unknown type never guessed");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_CHR), "same-name character device remains");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_BLK), "same-name block device remains");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_FIFO), "same-name fifo remains");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_SOCK), "same-name socket remains");
    expect(atomic_load(&queries) == before, "special or unknown entry types avoid matcher");
    expect(!susfs_directory_entry_hidden("Bin.mt.plus", 11, DT_DIR), "case-sensitive name");
    expect(!susfs_directory_entry_hidden("bin.mt.plus.extra", 17, DT_DIR), "no substring match");
    expect(!susfs_directory_entry_hidden(".", 1, DT_DIR), "dot preserved");
    expect(!susfs_directory_entry_hidden("..", 2, DT_DIR), "dotdot preserved");
    expect(!susfs_directory_entry_hidden("a/b", 3, DT_DIR), "slash rejected");
    expect(!susfs_directory_entry_hidden("a\0b", 3, DT_DIR), "embedded NUL rejected");
    expect(!susfs_directory_entry_hidden("bin.mt.plus\0", 12, DT_DIR), "trailing NUL is not name data");
    expect(!susfs_directory_entry_hidden(NULL, 11, DT_DIR), "null name rejected");
    expect(!susfs_directory_entry_hidden((const char *)1, -1, DT_DIR), "negative length rejected before read");
    expect(!susfs_directory_entry_hidden((const char *)1, NAME_MAX + 1, DT_DIR), "overlong length rejected before read");

    expect(!susfs_directory_inode_hidden(NULL), "null inode ignored");
    before = atomic_load(&lookups);
    struct inode regular = { .i_mode = S_IFREG | 0644, .alias = &alias };
    struct inode symlink = { .i_mode = S_IFLNK | 0777, .alias = &alias };
    expect(!susfs_directory_inode_hidden(&regular), "regular inode ignored");
    expect(!susfs_directory_inode_hidden(&symlink), "symlink inode ignored");
    expect(atomic_load(&lookups) == before, "non-directories never acquire alias");
    struct dentry regular_hidden = {
        .inode = &regular, .d_lock = PTHREAD_MUTEX_INITIALIZER,
        .d_parent = &parent, .d_name = { (const unsigned char *)"bin.mt.plus", 11 },
        .refs = ATOMIC_VAR_INIT(1),
    };
    struct dentry regular_keep = {
        .inode = &regular, .d_lock = PTHREAD_MUTEX_INITIALIZER,
        .d_parent = &parent, .d_name = { (const unsigned char *)"keep", 4 },
        .refs = ATOMIC_VAR_INIT(1),
    };
    regular.alias = &regular_hidden;
    expect(susfs_name_dentry_hidden(&regular_hidden), "regular actual alias exact name hidden");
    expect(!susfs_name_dentry_hidden(&regular_keep), "different hardlink name stays visible");
    expect(!susfs_directory_inode_hidden(&regular), "hidden hardlink never hides regular inode globally");
    expect(atomic_load(&regular_hidden.refs) == 1 && atomic_load(&regular_keep.refs) == 1,
           "borrowed dentry checks leave references untouched");
    expect(atomic_load(&lookups) == before, "regular name checks do not acquire aliases");
    regular_keep.d_name.name = (const unsigned char *)"bin.mt.plus";
    regular_keep.d_name.len = 11;
    expect(susfs_name_dentry_hidden(&regular_keep), "rename hardlink into selected name hides it");
    regular_hidden.d_name.name = (const unsigned char *)"renamed";
    regular_hidden.d_name.len = 7;
    expect(!susfs_name_dentry_hidden(&regular_hidden), "rename selected hardlink away reveals it");
    regular_hidden.d_name.name = (const unsigned char *)"bin.mt.plus";
    regular_hidden.d_name.len = 11;
    regular_hidden.inode = &symlink;
    expect(!susfs_name_dentry_hidden(&regular_hidden), "same-name symlink dentry stays visible");
    struct inode character = { .i_mode = S_IFCHR | 0600 };
    regular_hidden.inode = &character;
    expect(!susfs_name_dentry_hidden(&regular_hidden), "same-name device dentry stays visible");
    regular_hidden.inode = NULL;
    expect(!susfs_name_dentry_hidden(&regular_hidden), "negative borrowed dentry stays visible");
    expect(!susfs_name_dentry_hidden(NULL), "null borrowed dentry ignored");
    struct inode anonymous = { .i_mode = S_IFDIR | 0755 };
    expect(!susfs_directory_inode_hidden(&anonymous), "missing alias safe");
    expect(susfs_directory_inode_hidden(&directory), "matching connected directory hidden");
    expect(atomic_load(&alias.refs) == 1, "no lasting alias reference");
    applies = false;
    expect(!susfs_directory_inode_hidden(&directory), "selector exemption preserved");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_DIR), "entry uses same selector");
    applies = true;
    supported = false;
    before = atomic_load(&lookups);
    expect(!susfs_directory_inode_hidden(&directory), "disabled path feature ignores inode");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_DIR), "disabled path feature ignores entry");
    expect(atomic_load(&lookups) == before, "disabled path avoids alias lookup");
    supported = true;
    present = false;
    before = atomic_load(&lookups);
    expect(!susfs_directory_inode_hidden(&directory), "no name rules avoids inode alias work");
    expect(!susfs_directory_entry_hidden("bin.mt.plus", 11, DT_DIR), "no name rules ignores entry");
    expect(atomic_load(&lookups) == before, "zero name-rule count avoids alias lookup");
    present = true;

    alias.d_parent = &alias;
    expect(!susfs_directory_inode_hidden(&directory), "filesystem root not matched by alias label");
    alias.d_parent = &parent;
    alias.d_flags = DCACHE_DISCONNECTED;
    expect(!susfs_directory_inode_hidden(&directory), "disconnected alias ignored");
    alias.d_flags = 0;
    alias.inode = NULL;
    expect(!susfs_directory_inode_hidden(&directory), "negative alias ignored");
    alias.inode = &regular;
    expect(!susfs_directory_inode_hidden(&directory), "mismatched alias object ignored");
    alias.inode = &directory;
    alias.d_name.name = (const unsigned char *)1;
    alias.d_name.len = NAME_MAX + 1;
    expect(!susfs_directory_inode_hidden(&directory), "overlong alias rejected before pointer access");
    alias.d_name.name = NULL;
    alias.d_name.len = 11;
    expect(!susfs_directory_inode_hidden(&directory), "null alias bytes ignored");

    set_name("unrelated");
    expect(!susfs_directory_inode_hidden(&directory), "renamed away is immediately visible");
    set_name("bin.mt.plus");
    expect(susfs_directory_inode_hidden(&directory), "renamed into target immediately hidden");
    memset(live_name, 'x', NAME_MAX);
    live_name[NAME_MAX] = 0;
    alias.d_name.name = (const unsigned char *)live_name;
    alias.d_name.len = NAME_MAX;
    selected = live_name;
    expect(susfs_directory_inode_hidden(&directory), "NAME_MAX alias accepted and terminated");
    expect(susfs_directory_entry_hidden(live_name, NAME_MAX, DT_DIR), "NAME_MAX entry accepted");
    selected = "bin.mt.plus";
    set_name(".");
    expect(!susfs_directory_inode_hidden(&directory), "dot alias ignored");
    set_name("..");
    expect(!susfs_directory_inode_hidden(&directory), "dotdot alias ignored");
    set_name("bin.mt.plus");

    pthread_t thread;
    expect(!pthread_create(&thread, NULL, rename_worker, NULL), "start concurrent rename");
    for (unsigned int i = 0; i < 10000; ++i) {
        (void)susfs_directory_inode_hidden(&directory);
        expect(!held_lock, "query leaves no lock held");
    }
    expect(!pthread_join(thread, NULL), "join concurrent rename");
    expect(atomic_load(&alias.refs) == 1, "concurrent snapshots release every reference");
    expect(atomic_load(&lookups) == atomic_load(&releases) + 1, "every acquired alias released; one no-alias query");
    integration_tests();
    printf("DIRECTORY_NAME_HOOK_REGRESSION checks=%u passed=true kernel_calls=false production_helpers=true\n", atomic_load(&checks));
    return 0;
}
'''


def extract_callback(source: str, name: str) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    matches = list(re.finditer(rf"^(?:static\s+)?(?:bool|int)\s+{name}\s*\([^;{{}}]*\)\s*\{{", masked, flags=re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one actual callback {name}, found {len(matches)}")
    start = matches[0].start()
    opening = masked.index("{", start)
    depth = 0
    for cursor in range(opening, len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            return source[start:cursor + 1]
    raise ValueError(f"unbalanced callback {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "--evidence", dest="output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.output.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/susfs_dir_name.c"
    source = source_path.read_text(encoding="utf-8")
    production = re.sub(r"^#include[^\n]*\n", "", source, flags=re.M)
    path_source = (repo / "kernel/sus_path.c").read_text(encoding="utf-8")
    callback_names = ["sus_path_inode_getattr", "sus_path_inode_permission", "sus_path_dentry_hidden",
                      "sus_path_dentry_hidden_public", "sus_path_name_dentry_hidden",
                      ]
    callbacks = {name: extract_callback(path_source, name) for name in callback_names}
    content_source = (repo / "kernel/susfs_content.c").read_text(encoding="utf-8")
    callbacks["content_file_open"] = extract_callback(content_source, "content_file_open")
    generated = evidence / "directory-name-hook-production.c"
    # Fixture globals and set_name precede integration_tests, while main runs both.
    fixture, test_main = TESTS.split("int main(void)", 1)
    generated.write_text(PREAMBLE + "\n" + production + "\n" + INTEGRATION_DOUBLES + "\n" +
                         "\n\n".join(callbacks.values()) + "\n" + fixture + "\n" +
                         INTEGRATION_TESTS + "\nint main(void)" + test_main, encoding="utf-8")
    receipt = {
        "production_source": "kernel/susfs_dir_name.c",
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "production_sha256": hashlib.sha256(production.encode()).hexdigest(),
        "integration_sha256": {name: hashlib.sha256(piece.encode()).hexdigest() for name, piece in callbacks.items()},
        "limits": "Production helper TU and actual callbacks with typed host doubles and original-return trampoline double; not VFS/FUSE/CFI or device proof.",
        "runs": [],
    }
    for label, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("directory-name-hook-" + label + ".bin")
        command = [args.cc, "-std=c11", "-pthread", "-Wall", "-Wextra", "-Werror", *flags,
                   execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"DIRECTORY_NAME_HOOK_REGRESSION checks=(\d+) passed=true kernel_calls=false production_helpers=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=not run.returncode and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "directory-name-hook-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
