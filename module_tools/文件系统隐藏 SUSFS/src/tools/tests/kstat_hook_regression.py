#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run extracted production kstat readers with typed host/uaccess doubles.

The copied function bodies and macros are unmodified, except newline conversion.
This validates formatting, lookup integration and ABI bytes, not kernel probes,
real VFS/user faults, syscall installation, RCU concurrency or device effects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from path_hook_regression import extract, execution_path


PREAMBLE = r'''
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
#include "skp_group_objects.h"
#include "susfs_abi.h"
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
/* ARM64 compat_stat ABI, checked below against the production static asserts.
 * The host's own struct stat is deliberately never used. */
struct compat_stat {
    u32 st_dev, st_ino;
    uint16_t st_mode, st_nlink, st_uid, st_gid;
    u32 st_rdev;
    s32 st_size, st_blksize, st_blocks, st_atime;
    u32 st_atime_nsec;
    s32 st_mtime;
    u32 st_mtime_nsec;
    s32 st_ctime;
    u32 st_ctime_nsec, unused[2];
};
#define static_assert _Static_assert
#define dev_t u32
#define __user
#define __NR_newfstatat 79
#define __NR_fstat 80
#define __NR_statx 291
#define AT_EMPTY_PATH 0x1000
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define ATOMIC_INIT(value) { (value) }
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 12, 0)
#define READ_ONCE(x) (x)
#define MAJOR(d) ((u32)(d) >> 20)
#define MINOR(d) ((u32)(d) & 0xfffffU)
#define MKDEV(maj, min) (((u32)(maj) << 20) | (u32)(min))
static u32 new_encode_dev(u32 dev)
{
    unsigned int major = MAJOR(dev), minor = MINOR(dev);
    return (minor & 0xffU) | (major << 8) | ((minor & ~0xffU) << 12);
}
static u32 new_decode_dev(u32 dev)
{
    return MKDEV((dev & 0xfff00U) >> 8,
                 (dev & 0xffU) | ((dev >> 12) & 0xfff00U));
}
typedef struct { unsigned int value; } atomic_t;
static void atomic_inc(atomic_t *a) { a->value++; }
static unsigned int checks;
static void expect(bool condition, const char *message)
{
    checks++;
    if (!condition) { fprintf(stderr, "FAIL check=%u %s\n", checks, message); exit(1); }
}
struct seq_file { char *buf; size_t count, size; };
struct super_block { u32 s_dev; };
struct timespec64 { s64 tv_sec; long tv_nsec; };
struct inode {
    unsigned long i_ino; struct super_block *i_sb; u32 i_generation;
    unsigned int i_nlink, i_blkbits; long long i_size, i_blocks;
    struct timespec64 atime, mtime, ctime;
};
struct file { struct inode *inode; };
struct vm_area_struct { struct file *vm_file; };
struct pt_regs { unsigned long regs[31]; };
struct kretprobe_instance { _Alignas(max_align_t) unsigned char data[128]; };
static struct inode *file_inode(struct file *f) { return f->inode; }
static bool susfs_ptr_plausible(const void *p) { return p != NULL; }
static int scnprintf(char *buf, size_t capacity, const char *format, ...)
{
    va_list ap; va_start(ap, format); int n = vsnprintf(buf, capacity, format, ap); va_end(ap);
    return n < 0 ? n : (size_t)n >= capacity ? (int)capacity - 1 : n;
}
'''

DOUBLES = r'''
static struct sus_kstat_entry kstat_entries[32];
static int nkstat;
static bool kstat_table_lock;
#define spin_lock_irqsave(lock, flags) do { expect(!*(lock), "table lock is exclusive"); legacy_lookup_calls++; *(lock) = true; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { expect(*(lock) && (flags) == 0, "table unlock owns lock"); *(lock) = false; } while (0)
static unsigned char *user_start;
static size_t user_length;
static void *compat_ptr(u32 value)
{
    if(!value)return NULL;
    expect(value==0x12345678U,"compat pathname is a zero-extended 32-bit address");
    return user_start;
}
static unsigned int read_calls, write_calls, fail_read_at, fail_write_at;
static unsigned int query_calls, legacy_gate_calls, legacy_lookup_calls, maps_query_calls;
static u32 queried_igen;
static bool redirect_priority;
static u64 queried_ino, queried_dev;
static unsigned int expected_key_reads;
static bool retire_after_query;
static bool path_content_present,fd_content_present;
static unsigned int content_path_calls,content_fd_calls,content_fd_expected=17;
static u64 content_path_bytes;
static unsigned long content_fd_bytes;
static bool skp_policy_content_stat_size(u64 dev,u64 ino,u64 *size)
{
    content_path_calls++;
    expect(!kstat_table_lock&&dev==queried_dev&&ino==queried_ino,"path content uses raw queried identity outside lock");
    if(!path_content_present)return false;
    *size=content_path_bytes;return true;
}
static bool susfs_content_fd_size(unsigned int fd,u64 ino,u64 dev,unsigned long *size)
{
    content_fd_calls++;
    expect(!kstat_table_lock&&dev==queried_dev&&ino==queried_ino,"FD content uses raw queried identity outside lock");
    if(!fd_content_present||fd!=content_fd_expected)return false;
    *size=content_fd_bytes;return true;
}
static bool upstream_gate = true;
static enum skp_object_query_mode query_mode = SKP_OBJECT_GROUPED;
static struct skp_kstat_query_result query_result;
static atomic_t n_kstat_map_hits, n_kstat_map_rewrites;
static size_t uaccess_copy(void *destination, const void *source, size_t length, bool write)
{
    uintptr_t pointer = (uintptr_t)(write ? destination : source);
    unsigned int call = write ? ++write_calls : ++read_calls;
    expect(!kstat_table_lock, "uaccess never runs under the table spinlock");
    expect(pointer >= (uintptr_t)user_start && length <= user_length &&
           pointer - (uintptr_t)user_start <= user_length - length,
           "uaccess remains inside the supplied ABI buffer");
    if (call == (write ? fail_write_at : fail_read_at)) return length;
    if (write && retire_after_query) {
        retire_after_query = false;
        memset(&query_result.values, 0, sizeof(query_result.values));
    }
    memcpy(destination, source, length); return 0;
}
static size_t copy_from_user(void *destination, const void *source, size_t length)
{ return uaccess_copy(destination, source, length, false); }
static size_t copy_to_user(void *destination, const void *source, size_t length)
{ return uaccess_copy(destination, source, length, true); }
static enum skp_object_query_mode skp_policy_kstat_query(u64 dev, u64 ino,
                                                       struct skp_kstat_query_result *result)
{
    query_calls++; queried_dev = dev; queried_ino = ino;
    expect(read_calls == expected_key_reads * query_calls, "all user-key reads precede snapshot query");
    expect(!kstat_table_lock, "snapshot query precedes independent legacy table lock");
    *result = query_result; return query_mode;
}
static enum skp_object_query_mode skp_policy_kstat_maps_query(u64 dev, u64 ino, u32 igen,
                                                       struct skp_kstat_query_result *result)
{
    enum skp_object_query_mode mode = skp_policy_kstat_query(dev, ino, result);
    maps_query_calls++; queried_igen = igen;
    if (mode == SKP_OBJECT_GROUPED && redirect_priority) {
        result->matched = 0; memset(&result->values, 0, sizeof(result->values));
    }
    return mode;
}
static bool susfs_is_current_proc_umounted_app(void)
{ legacy_gate_calls++; return upstream_gate; }
typedef ptrdiff_t ssize_t;
typedef long long loff_t;
struct test_lock { bool held; };
static struct test_lock kstat_lock, kstat_maps_ctl_lock;
static void mutex_lock(struct test_lock *lock)
{ expect(!lock->held, "mutex is not recursive"); lock->held = true; }
static void mutex_unlock(struct test_lock *lock)
{ expect(lock->held, "mutex unlock owns lock"); lock->held = false; }
#define lockdep_assert_held(lock) expect((lock)->held, "operation holds expected writer mutex")
struct kretprobe { unsigned long address; };
static struct kretprobe krp_kstat_map_vma;
static bool kstat_maps_exiting, kstat_maps_registered, grouped_active;
static unsigned int register_calls, forget_calls, uid;
static int register_error;
static int register_kretprobe(struct kretprobe *probe)
{
    expect(kstat_maps_ctl_lock.held && probe == &krp_kstat_map_vma, "registration owns maps lifecycle mutex");
    register_calls++; probe->address = 1; return register_error;
}
static void susfs_krp_forget_addr(struct kretprobe *probe)
{
    expect(kstat_maps_ctl_lock.held && probe == &krp_kstat_map_vma, "failed registration reset owns maps mutex");
    forget_calls++; probe->address = 0;
}
static void noop_log(const char *format, ...) { (void)format; }
#define pr_warn noop_log
#define SUSFS_LOGI noop_log
struct test_uid { unsigned int val; };
static struct test_uid current_uid(void) { struct test_uid result = { uid }; return result; }
static bool skp_policy_paths_active(void)
{ expect(kstat_lock.held, "legacy ownership checked while writer mutex is held"); return grouped_active; }
static bool susfs_abi_path_ok(const char *path, size_t length) { return memchr(path, 0, length) != NULL; }
struct dentry { struct inode *inode; };
struct path { struct dentry *dentry; };
static struct super_block fixture_sb = { .s_dev = MKDEV(8, 7) };
static struct inode fixture_inode = { .i_ino = 43, .i_sb = &fixture_sb,
    .i_nlink = 1, .i_blkbits = 12, .i_size = 123, .i_blocks = 8,
    .atime = { 1700000000, 100 }, .mtime = { 1700000001, 200 }, .ctime = { 1700000002, 300 } };
static struct dentry fixture_dentry = { .inode = &fixture_inode };
static unsigned int prepare_calls, release_calls;
static bool takeover_during_prepare, remove_during_prepare;
static int prepare_error;
static int kern_path(const char *name, int flags, struct path *path)
{
    (void)flags;
    expect(!kstat_lock.held && !kstat_maps_ctl_lock.held && !kstat_table_lock,
           "VFS resolution runs outside all writer/table locks");
    expect(!strcmp(name, "/fixture"), "writer resolves owned fixture");
    prepare_calls++;
    if (remove_during_prepare) {
        mutex_lock(&kstat_lock); nkstat = 0; mutex_unlock(&kstat_lock);
        remove_during_prepare = false;
    }
    if (prepare_error) return prepare_error;
    path->dentry = &fixture_dentry; return 0;
}
static void path_put(struct path *path)
{
    expect(path->dentry == &fixture_dentry && !kstat_lock.held && !kstat_maps_ctl_lock.held && !kstat_table_lock,
           "VFS reference release runs outside all writer/table locks");
    release_calls++;
    if (takeover_during_prepare) {
        mutex_lock(&kstat_lock); grouped_active = true; mutex_unlock(&kstat_lock);
        takeover_during_prepare = false;
    }
    path->dentry = NULL;
}
static struct inode *d_backing_inode(struct dentry *dentry) { return dentry->inode; }
static struct timespec64 inode_get_atime(struct inode *inode) { return inode->atime; }
static struct timespec64 inode_get_mtime(struct inode *inode) { return inode->mtime; }
static struct timespec64 inode_get_ctime(struct inode *inode) { return inode->ctime; }
static long strscpy(char *output, const char *input, size_t capacity)
{
    size_t n = strlen(input); expect(n < capacity, "owned fixture path fits legacy slot");
    memcpy(output, input, n + 1); return (long)n;
}
static int kstrtoll(const char *text, unsigned int base, long long *value)
{
    char *end; errno = 0; *value = strtoll(text, &end, base);
    return errno || !text[0] || *end ? -EINVAL : 0;
}
struct hook_double { bool installed; };
static struct hook_double kstat_hooks[14];
'''

TESTS = r'''
static struct kstat_call_counters counters;
static struct kstat_call_state state = { .cnt = &counters, .compat = false };
static void reset(void *buffer, size_t length, unsigned int reads)
{
    memset(buffer, 0xa5, length); user_start = buffer; user_length = length;
    read_calls = write_calls = fail_read_at = fail_write_at = query_calls = 0;
    legacy_gate_calls = legacy_lookup_calls = maps_query_calls = queried_igen = 0; expected_key_reads = reads;
    redirect_priority = false;
    path_content_present=fd_content_present=false;content_path_calls=content_fd_calls=0;
    content_path_bytes=0;content_fd_bytes=0;content_fd_expected=17;state.fd_query=false;state.fd=0;
    query_mode = SKP_OBJECT_GROUPED; upstream_gate = true; nkstat = 0;
    retire_after_query = false;
    memset(&query_result, 0, sizeof(query_result)); query_result.matched = 1;
    query_result.values.ino = 0x100000017ULL;
    query_result.values.dev_encoded = new_encode_dev(MKDEV(254, 0x12345));
    query_result.values.nlink = 7; query_result.values.size = 0x100000023LL;
    query_result.values.atime_sec = 0x1122334455667788LL;
    query_result.values.mtime_sec = -0x112233445566LL;
    query_result.values.ctime_sec = 1700000000;
    query_result.values.atime_nsec = 123; query_result.values.mtime_nsec = 456;
    query_result.values.ctime_nsec = 789; query_result.values.blocks = 0x100000005LL;
    query_result.values.blksize = 4096; query_result.values.flags = SKP_KSTAT_FLAGS_ALL;
}
static void put(void *buffer, size_t offset, u64 value, size_t width)
{ memcpy((unsigned char *)buffer + offset, &value, width); }
static u64 get(const void *buffer, size_t offset, size_t width)
{ u64 value = 0; memcpy(&value, (const unsigned char *)buffer + offset, width); return value; }
static void native_key(void *buffer)
{
    put(buffer, ST_INO_OFF, 0x20000002bULL, 8);
    put(buffer, ST_DEV_OFF, new_encode_dev(MKDEV(8, 0x34567)), 8);
}
static void test_native(void)
{
    unsigned char buf[128], before[128];
    reset(buf, sizeof(buf), 2); native_key(buf);
    expect(susfs_kstat_spoof_statbuf(&state, (unsigned long)buf), "group native works when nkstat is zero");
    expect(query_calls == 1 && legacy_gate_calls == 0 && queried_ino == 0x20000002bULL &&
           queried_dev == MKDEV(8, 0x34567), "native uses full ino and raw decoded dev once");
    expect(get(buf, ST_INO_OFF, 8) == query_result.values.ino, "native ino exact");
    expect(get(buf, ST_DEV_OFF, 8) == query_result.values.dev_encoded, "native encoded dev exact");
    expect(get(buf, ST_SIZE_OFF, 8) == (u64)query_result.values.size, "native size exact");
    expect(get(buf, ST_NLINK_OFF, 4) == 7 && get(buf, ST_BLKSIZE_OFF, 4) == 4096, "native short fields");
    expect(get(buf, ST_BLOCKS_OFF, 8) == (u64)query_result.values.blocks, "native blocks exact");
    expect(get(buf, ST_ATIME_OFF, 8) == (u64)query_result.values.atime_sec &&
           get(buf, ST_MTIME_OFF, 8) == (u64)query_result.values.mtime_sec &&
           get(buf, ST_CTIME_OFF, 8) == (u64)query_result.values.ctime_sec, "native signed timestamp seconds");
    expect(get(buf, ST_ATIME_NSEC_OFF, 8) == 123 && get(buf, ST_MTIME_NSEC_OFF, 8) == 456 &&
           get(buf, ST_CTIME_NSEC_OFF, 8) == 789, "native timestamp ns exact");
    reset(buf, sizeof(buf), 2); native_key(buf); memcpy(before, buf, sizeof(buf));
    query_result.matched = 0; nkstat = 1; kstat_entries[0].target_ino = 0x20000002bULL;
    kstat_entries[0].target_dev = new_encode_dev(MKDEV(8, 0x34567));
    kstat_entries[0].flags = KSTAT_SPOOF_INO; kstat_entries[0].spoofed_ino = 99;
    expect(!susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) &&
           !memcmp(buf, before, sizeof(buf)) && !legacy_gate_calls,
           "group miss is authoritative despite matching legacy table");
    query_mode = SKP_OBJECT_LEGACY_SUBJECT; query_result.legacy_allowed = 0;
    expect(!susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && !legacy_gate_calls,
           "legacy subject negative never invokes upstream predicate");
    query_result.legacy_allowed = 1;
    expect(susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && get(buf, ST_INO_OFF, 8) == 99,
           "legacy subject positive uses legacy table");
    reset(buf, sizeof(buf), 2); native_key(buf); query_mode = SKP_OBJECT_UPSTREAM; upstream_gate = false;
    expect(!susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && legacy_gate_calls == 1,
           "upstream mode retains pure upstream gate");
    for (unsigned int n = 1; n <= 2; n++) {
        reset(buf, sizeof(buf), 2); native_key(buf); fail_read_at = n;
        expect(!susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && !query_calls && !write_calls,
               "failed key read does not query or write");
    }
    for (unsigned int n = 1; n <= 12; n++) {
        reset(buf, sizeof(buf), 2); native_key(buf); fail_write_at = n;
        expect(!susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && query_calls == 1,
               "write fault reports failure without another snapshot query");
    }
    reset(buf, sizeof(buf), 2); native_key(buf); retire_after_query = true;
    expect(susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) && query_calls == 1 &&
           get(buf, ST_INO_OFF, 8) == 0x100000017ULL && get(buf, ST_BLOCKS_OFF, 8) == 0x100000005ULL &&
           get(buf, ST_ATIME_OFF, 8) == 0x1122334455667788ULL,
           "retired result storage cannot change the copied spoof payload during uaccess");
}
static void test_compat(void)
{
    unsigned char buf[128];
    unsigned int narrow;
    reset(buf, sizeof(buf), 2);
    put(buf, STAT64_ST_DEV_OFF, new_encode_dev(MKDEV(8, 0x34567)), 8);
    put(buf, STAT64_ST_BROKEN_INO_OFF, 0x2b, 4); put(buf, STAT64_ST_INO_OFF, 0x20000002bULL, 8);
    narrow = counters.narrow.value;
    expect(susfs_kstat_spoof_compat_statbuf(&state, (unsigned long)buf), "compat stat64 group works without legacy count");
    expect(queried_ino == 0x20000002bULL, "compat stat64 matches full ino, not broken truncated field");
    expect(get(buf, STAT64_ST_INO_OFF, 8) == query_result.values.ino &&
           get(buf, STAT64_ST_BROKEN_INO_OFF, 4) == 0x17, "compat stat64 writes both ino fields");
    expect(get(buf, STAT64_ST_SIZE_OFF, 8) == (u64)query_result.values.size &&
           get(buf, STAT64_ST_BLOCKS_OFF, 8) == (u64)query_result.values.blocks, "compat stat64 retains 64-bit size and blocks");
    expect(get(buf, STAT64_ST_ATIME_OFF, 4) == 0xa5a5a5a5U &&
           get(buf, STAT64_ST_MTIME_OFF, 4) == 0xa5a5a5a5U &&
           get(buf, STAT64_ST_CTIME_OFF, 4) == 1700000000 && counters.narrow.value == narrow + 2,
           "compat stat64 preserves overflowing seconds and writes fitting seconds");
    reset(buf, sizeof(buf), 2);
    put(buf, COMPAT_STAT_ST_DEV_OFF, new_encode_dev(MKDEV(8, 0x34567)), 4);
    put(buf, COMPAT_STAT_ST_INO_OFF, 43, 4); query_result.values.nlink = 65536;
    narrow = counters.narrow.value;
    expect(susfs_kstat_spoof_compat_stat(&state, (unsigned long)buf), "old compat writes remaining fitting fields");
    expect(get(buf, COMPAT_STAT_ST_INO_OFF, 4) == 43 && get(buf, COMPAT_STAT_ST_NLINK_OFF, 2) == 0xa5a5 &&
           get(buf, COMPAT_STAT_ST_SIZE_OFF, 4) == 0xa5a5a5a5U &&
           get(buf, COMPAT_STAT_ST_BLOCKS_OFF, 4) == 0xa5a5a5a5U && counters.narrow.value == narrow + 6,
           "old compat preserves unrepresentable ino nlink size blocks and seconds");
    expect(get(buf, COMPAT_STAT_ST_ATIME_NSEC_OFF, 4) == 123 &&
           get(buf, COMPAT_STAT_ST_CTIME_OFF, 4) == 1700000000, "old compat continues with representable ns and seconds");
    for (unsigned int layout = 0; layout < 2; layout++) {
        reset(buf, sizeof(buf), 2);
        put(buf, layout ? COMPAT_STAT_ST_INO_OFF : STAT64_ST_INO_OFF, 43, layout ? 4 : 8);
        put(buf, layout ? COMPAT_STAT_ST_DEV_OFF : STAT64_ST_DEV_OFF, new_encode_dev(MKDEV(8, 7)), layout ? 4 : 8);
        query_result.values.flags = KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_SEC;
        query_result.values.atime_sec = layout ? -2147483647LL - 1 : 2147483648LL;
        query_result.values.mtime_sec = layout ? 2147483647LL : 4294967295LL;
        expect(layout ? susfs_kstat_spoof_compat_stat(&state, (unsigned long)buf) :
                        susfs_kstat_spoof_compat_statbuf(&state, (unsigned long)buf), "compat ABI second boundaries fit");
        expect(get(buf, layout ? COMPAT_STAT_ST_ATIME_OFF : STAT64_ST_ATIME_OFF, 4) == 0x80000000U &&
               get(buf, layout ? COMPAT_STAT_ST_MTIME_OFF : STAT64_ST_MTIME_OFF, 4) == (layout ? 0x7fffffffU : 0xffffffffU),
               "compat signed old-stat and unsigned stat64 seconds retain their actual ABI range");
    }
}
static void statx_key(void *buffer)
{
    put(buffer, kstat_statx_offs.ino, 0x20000002bULL, 8);
    put(buffer, kstat_statx_offs.dev, 8, 4); put(buffer, kstat_statx_offs.dev_minor, 0x34567, 4);
    put(buffer, kstat_statx_offs.mask, STATX_BASIC_STATS, 4);
}
static void test_statx(void)
{
    unsigned char buf[256];
    reset(buf, sizeof(buf), 4); statx_key(buf);
    expect(susfs_kstat_spoof_statx(&state, (unsigned long)buf, STATX_BASIC_STATS), "statx group works with zero legacy count");
    expect(query_calls == 1 && queried_dev == MKDEV(8, 0x34567), "statx rebuilds raw device from both halves");
    expect(get(buf, kstat_statx_offs.dev, 4) == 254 && get(buf, kstat_statx_offs.dev_minor, 4) == 0x12345,
           "statx splits spoofed encoded dev correctly");
    expect(get(buf, kstat_statx_offs.atime_sec, 8) == (u64)query_result.values.atime_sec &&
           get(buf, kstat_statx_offs.mtime_sec, 8) == (u64)query_result.values.mtime_sec,
           "statx writes all eight signed timestamp bytes, including high halves");
    expect(get(buf, kstat_statx_offs.atime_sec + 12, 4) == 0xa5a5a5a5U,
           "statx leaves timestamp reserved bytes unchanged");
    for (unsigned int n = 1; n <= 4; n++) {
        reset(buf, sizeof(buf), 4); statx_key(buf); fail_read_at = n;
        expect(!susfs_kstat_spoof_statx(&state, (unsigned long)buf, STATX_BASIC_STATS) && !query_calls && !write_calls,
               "statx read faults precede snapshot query");
    }
    reset(buf, sizeof(buf), 4); statx_key(buf); put(buf, kstat_statx_offs.mask, 0, 4);
    query_result.values.flags = KSTAT_SPOOF_INO | KSTAT_SPOOF_ATIME_TV_SEC;
    expect(!susfs_kstat_spoof_statx(&state, (unsigned long)buf, 0) && !write_calls,
           "statx unrequested unavailable fields stay unchanged");
    expect(susfs_kstat_spoof_statx(&state, (unsigned long)buf, STATX_INO) && write_calls == 1 &&
           get(buf, kstat_statx_offs.atime_sec, 8) == 0xa5a5a5a5a5a5a5a5ULL,
           "statx requested mask permits only selected returned field");
}
static size_t content_size_offset(unsigned int layout)
{
    return layout==0?ST_SIZE_OFF:layout==1?STAT64_ST_SIZE_OFF:layout==2?COMPAT_STAT_ST_SIZE_OFF:kstat_statx_offs.size;
}
static void content_layout_key(void *buffer,unsigned int layout)
{
    size_t ino=layout==0?ST_INO_OFF:layout==1?STAT64_ST_INO_OFF:layout==2?COMPAT_STAT_ST_INO_OFF:kstat_statx_offs.ino;
    size_t dev=layout==0?ST_DEV_OFF:layout==1?STAT64_ST_DEV_OFF:layout==2?COMPAT_STAT_ST_DEV_OFF:kstat_statx_offs.dev;
    put(buffer,ino,43,layout==2?4:8);
    put(buffer,dev,layout==3?8:new_encode_dev(MKDEV(8,0x34567)),layout<2?8:4);
    if(layout==3){put(buffer,kstat_statx_offs.dev_minor,0x34567,4);put(buffer,kstat_statx_offs.mask,STATX_BASIC_STATS,4);}
    put(buffer,content_size_offset(layout),91,layout==2?4:8);
}
static bool content_layout_apply(unsigned int layout,void *buffer)
{
    switch(layout){
    case 0:return susfs_kstat_spoof_statbuf(&state,(unsigned long)buffer);
    case 1:return susfs_kstat_spoof_compat_statbuf(&state,(unsigned long)buffer);
    case 2:return susfs_kstat_spoof_compat_stat(&state,(unsigned long)buffer);
    default:return susfs_kstat_spoof_statx(&state,(unsigned long)buffer,STATX_BASIC_STATS);
    }
}
static void test_content_size_views(void)
{
    unsigned char buf[256],before[256];
    for(unsigned int layout=0;layout<4;layout++){
        const size_t width=layout==2?4:8,offset=content_size_offset(layout);
        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);query_result.matched=0;
        path_content_present=true;content_path_bytes=113;memcpy(before,buf,sizeof(buf));put(before,offset,113,width);
        expect(content_layout_apply(layout,buf),"path stat exposes current content length across all ABI layouts");
        expect(get(buf,offset,width)==113&&!memcmp(buf,before,sizeof(buf)),"content path stat changes only returned SIZE");
        expect(content_path_calls==1&&!content_fd_calls,"ordinary path never selects descriptor lookup");

        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);query_result.matched=0;
        state.fd_query=true;state.fd=17;fd_content_present=path_content_present=true;
        content_fd_bytes=47;content_path_bytes=701;
        expect(content_layout_apply(layout,buf)&&get(buf,offset,width)==47,"bound old FD size is independent of current path version");
        expect(content_fd_calls==1&&!content_path_calls,"FD stat only selects descriptor-owned snapshot");
        path_content_present=false;content_fd_bytes=31;content_path_calls=content_fd_calls=query_calls=read_calls=write_calls=0;
        content_layout_key(buf,layout);
        expect(content_layout_apply(layout,buf)&&get(buf,offset,width)==31,"bound FD size survives path rule removal");
        expect(content_fd_calls==1&&!content_path_calls,"removed path rule cannot replace FD size");

        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);query_result.matched=0;
        state.fd_query=true;state.fd=18;fd_content_present=path_content_present=true;
        content_fd_bytes=47;content_path_bytes=701;memcpy(before,buf,sizeof(buf));
        expect(!content_layout_apply(layout,buf)&&!memcmp(buf,before,sizeof(buf)),"unwrapped FD does not borrow current path content length");
        expect(content_fd_calls==1&&!content_path_calls,"unwrapped FD miss cannot fall back to path rule");

        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);
        query_result.values.flags=KSTAT_SPOOF_SIZE;query_result.values.size=257;
        fd_content_present=path_content_present=true;content_fd_bytes=47;content_path_bytes=701;
        state.fd_query=true;state.fd=17;
        expect(content_layout_apply(layout,buf)&&get(buf,offset,width)==257,"explicit kstat SIZE wins over FD content size");
        expect(!content_fd_calls&&!content_path_calls,"explicit SIZE avoids content lookup");
        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);
        query_result.values.flags=KSTAT_SPOOF_SIZE;query_result.values.size=269;
        path_content_present=true;content_path_bytes=701;
        expect(content_layout_apply(layout,buf)&&get(buf,offset,width)==269,"explicit kstat SIZE also wins over current path content");
        expect(!content_fd_calls&&!content_path_calls,"explicit path SIZE avoids content lookup");

        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);
        query_result.values.flags=KSTAT_SPOOF_INO;query_result.values.ino=500;
        path_content_present=true;content_path_bytes=113;
        expect(content_layout_apply(layout,buf)&&get(buf,offset,width)==113,"content SIZE merges with other explicit kstat fields");
        size_t ino=layout==0?ST_INO_OFF:layout==1?STAT64_ST_INO_OFF:layout==2?COMPAT_STAT_ST_INO_OFF:kstat_statx_offs.ino;
        expect(get(buf,ino,width)==500,"merging content length preserves explicit inode field");

        reset(buf,sizeof(buf),layout==3?4:2);content_layout_key(buf,layout);query_result.matched=0;memcpy(before,buf,sizeof(buf));
        expect(!content_layout_apply(layout,buf)&&!memcmp(before,buf,sizeof(buf)),"absent content preserves ordinary stat bytes");
    }
}
static void test_content_fd_classification(void)
{
    char name[16];unsigned long args[6]={17,0,0,0,0,0};
    const struct {long nr;bool compat;unsigned int flag_arg;} cases[]={
        {__NR_newfstatat,false,3},{__NR_statx,false,2},
        {COMPAT_FSTATAT64_NR,true,3},{COMPAT_STATX_NR,true,2}
    };
    for(unsigned int i=0;i<ARRAY_SIZE(cases);i++){
        reset(name,sizeof(name),0);name[0]=0;args[1]=cases[i].compat?0x12345678U:(unsigned long)name;
        args[2]=args[3]=0;args[cases[i].flag_arg]=AT_EMPTY_PATH;
        expect(kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&read_calls==1,"empty pathname with AT_EMPTY_PATH selects FD size");
        reset(name,sizeof(name),0);strcpy(name,"ordinary");
        expect(!kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&read_calls==1,"nonempty pathname with AT_EMPTY_PATH remains path size query");
        reset(name,sizeof(name),0);name[0]=0;args[cases[i].flag_arg]=0;
        expect(!kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&!read_calls,"missing AT_EMPTY_PATH cannot select descriptor size");
        args[cases[i].flag_arg==2?3:2]=AT_EMPTY_PATH;
        expect(!kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&!read_calls,"AT_EMPTY_PATH in another argument slot cannot select descriptor size");
        args[2]=args[3]=0;
        reset(name,sizeof(name),0);args[1]=0;args[cases[i].flag_arg]=AT_EMPTY_PATH;
        expect(kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&!read_calls,"NULL pathname with AT_EMPTY_PATH selects descriptor size");
        reset(name,sizeof(name),0);name[0]=0;args[1]=cases[i].compat?0x12345678U:(unsigned long)name;fail_read_at=1;
        expect(!kstat_content_fd_query(cases[i].nr,cases[i].compat,args)&&read_calls==1,"unreadable pathname cannot be guessed as empty");
    }
    reset(name,sizeof(name),0);args[1]=0;
    expect(kstat_content_fd_query(__NR_fstat,false,args)&&!read_calls,"native fstat always selects descriptor size");
    expect(kstat_content_fd_query(COMPAT_FSTAT64_NR,true,args)&&!read_calls,"compat fstat64 always selects descriptor size");
    expect(kstat_content_fd_query(COMPAT_FSTAT_NR,true,args)&&!read_calls,"old compat fstat always selects descriptor size");
    expect(!kstat_content_fd_query(__NR_fstat,true,args)&&!read_calls,"compat ABI cannot use native fstat number");
    expect(!kstat_content_fd_query(COMPAT_FSTAT_NR,false,args)&&!read_calls,"native ABI cannot use compat fstat number");
    expect(!kstat_content_fd_query(__NR_statx,true,args)&&!read_calls,"compat ABI cannot use native statx number");
    expect(!kstat_content_fd_query(COMPAT_STATX_NR,false,args)&&!read_calls,"native ABI cannot use compat statx number");
}
static void test_maps(void)
{
    char buf[512]; struct seq_file m = { .buf = buf, .count = 0, .size = sizeof(buf) };
    struct super_block sb = { .s_dev = MKDEV(8, 7) };
    struct inode ino = { .i_ino = 43, .i_sb = &sb, .i_generation = 71 };
    struct file file = { .inode = &ino }; struct vm_area_struct vma = { .vm_file = &file };
    struct pt_regs regs = { .regs = { (unsigned long)&m, (unsigned long)&vma } };
    struct kretprobe_instance instance;
    reset(buf, sizeof(buf), 0); m.count = 0;
    const char *line = "1000-2000 r--p 0 08:07 43 /fixture\n";
    memcpy(buf, line, strlen(line)); m.count = strlen(line);
    expect(kstat_map_vma_entry(&instance, &regs) == 0, "maps records entry interval");
    expect(kstat_map_vma_ret(&instance, &regs) == 0 && query_calls == 0 && !memcmp(buf, line, strlen(line)),
           "skipped VMA does not query or rewrite identical earlier line");
    memcpy(buf + m.count, line, strlen(line)); m.count += strlen(line);
    expect(kstat_map_vma_ret(&instance, &regs) == 0 && query_calls == 1 && !memcmp(buf, line, strlen(line)),
           "maps current interval only preserves earlier identical line");
    expect(memmem_for_test(buf + strlen(line), m.count - strlen(line), "fe:12345 4294967319"),
           "maps renders spoofed raw device and full ino in current interval");
    expect(maps_query_calls == 1 && queried_igen == 71 && queried_ino == 43 && queried_dev == MKDEV(8,7),
           "maps alone passes actual inode generation to the priority query");
    size_t saved = m.count; expect(!kstat_buf_replace(&m, m.count, "08", 2, "99", 2) && m.count == saved,
                                 "empty appended interval cannot modify buffer");
    m.count = m.size; expect(!kstat_buf_replace(&m, 0, "08", 2, "99", 2), "overflowed seq buffer is not edited");
    m.count = 3; memcpy(buf, "abc", 3); m.size = 4;
    expect(!kstat_buf_replace(&m, 0, "a", 1, "AA", 2), "growing to seq capacity fails safely");
}
static void test_all_authoritative_misses(void)
{
    unsigned char buf[256], before[256];
    for (unsigned int family = 0; family < 4; family++) {
        reset(buf, sizeof(buf), family == 3 ? 4 : 2);
        size_t ino_offset = family == 0 ? ST_INO_OFF : family == 1 ? STAT64_ST_INO_OFF :
                            family == 2 ? COMPAT_STAT_ST_INO_OFF : kstat_statx_offs.ino;
        size_t dev_offset = family == 0 ? ST_DEV_OFF : family == 1 ? STAT64_ST_DEV_OFF :
                            family == 2 ? COMPAT_STAT_ST_DEV_OFF : kstat_statx_offs.dev;
        put(buf, ino_offset, 43, family == 2 ? 4 : 8);
        put(buf, dev_offset, family == 3 ? 8 : new_encode_dev(MKDEV(8, 7)), family == 0 || family == 1 ? 8 : 4);
        if (family == 3) { put(buf, kstat_statx_offs.dev_minor, 7, 4); put(buf, kstat_statx_offs.mask, STATX_BASIC_STATS, 4); }
        query_result.matched = 0; nkstat = 1;
        kstat_entries[0].target_ino = 43; kstat_entries[0].target_dev = new_encode_dev(MKDEV(8, 7));
        kstat_entries[0].flags = KSTAT_SPOOF_INO; kstat_entries[0].spoofed_ino = 99;
        memcpy(before, buf, sizeof(buf));
        bool changed = family == 0 ? susfs_kstat_spoof_statbuf(&state, (unsigned long)buf) :
                       family == 1 ? susfs_kstat_spoof_compat_statbuf(&state, (unsigned long)buf) :
                       family == 2 ? susfs_kstat_spoof_compat_stat(&state, (unsigned long)buf) :
                                     susfs_kstat_spoof_statx(&state, (unsigned long)buf, STATX_BASIC_STATS);
        expect(!changed && query_calls == 1 && !legacy_lookup_calls && !legacy_gate_calls &&
               !write_calls && !memcmp(buf, before, sizeof(buf)),
               "every syscall ABI honors grouped negative without legacy fallback");
    }
    reset(buf, sizeof(buf), 0); query_result.matched = 0;
    struct seq_file m = { .buf = (char *)buf, .count = 0, .size = sizeof(buf) };
    struct super_block sb = { .s_dev = MKDEV(8, 7) };
    struct inode ino = { .i_ino = 43, .i_sb = &sb, .i_generation = 71 };
    struct file file = { .inode = &ino }; struct vm_area_struct vma = { .vm_file = &file };
    struct pt_regs regs = { .regs = { (unsigned long)&m, (unsigned long)&vma } };
    struct kretprobe_instance instance;
    kstat_map_vma_entry(&instance, &regs);
    const char *line = "1000-2000 r--p 0 08:07 43 /fixture\n";
    memcpy(buf, line, strlen(line)); m.count = strlen(line);
    nkstat = 1; kstat_entries[0].target_ino = 43; kstat_entries[0].target_dev = new_encode_dev(MKDEV(8, 7));
    expect(kstat_map_vma_ret(&instance, &regs) == 0 && query_calls == 1 &&
           !legacy_lookup_calls && !legacy_gate_calls && !memcmp(buf, line, strlen(line)),
           "maps honors authoritative negative despite matching legacy table");
}
static void test_maps_redirect_priority(void)
{
    char buf[512]; struct seq_file m = { .buf = buf, .count = 0, .size = sizeof(buf) };
    struct super_block sb = { .s_dev = MKDEV(8,7) };
    struct inode ino = { .i_ino = 43, .i_sb = &sb, .i_generation = 71 };
    struct file file = { .inode = &ino }; struct vm_area_struct vma = { .vm_file = &file };
    struct pt_regs regs = { .regs = { (unsigned long)&m, (unsigned long)&vma } };
    struct kretprobe_instance instance;
    const char *line = "1000-2000 r--p 0 08:07 43 /redirect-target\n";
    reset(buf,sizeof(buf),0); redirect_priority = true; nkstat = 1;
    kstat_entries[0].target_ino = 43; kstat_entries[0].target_dev = new_encode_dev(MKDEV(8,7));
    kstat_entries[0].flags = KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV;
    kstat_entries[0].spoofed_ino = 99; kstat_entries[0].spoofed_dev = new_encode_dev(MKDEV(254,75));
    kstat_map_vma_entry(&instance,&regs);
    memcpy(buf,line,strlen(line)); m.count = strlen(line);
    expect(kstat_map_vma_ret(&instance,&regs) == 0 && maps_query_calls == 1 && queried_igen == 71 &&
           !memcmp(buf,line,strlen(line)) && !legacy_lookup_calls && !legacy_gate_calls,
           "authoritative redirect priority preserves actual maps key for either callback order");
    /* A non-redirected maps object retains kstat; stat syscalls never use
     * this priority policy, even on the same file identity. */
    unsigned char statbuf[128]; reset(statbuf,sizeof(statbuf),2); native_key(statbuf); redirect_priority = true;
    expect(susfs_kstat_spoof_statbuf(&state,(unsigned long)statbuf) && !maps_query_calls &&
           get(statbuf,ST_INO_OFF,8) == 0x100000017ULL, "generic stat query unchanged by maps-only priority");
    for (unsigned int legacy = 0; legacy < 2; ++legacy) {
        reset(buf,sizeof(buf),0); m.count = 0; redirect_priority = true;
        query_mode = legacy ? SKP_OBJECT_LEGACY_SUBJECT : SKP_OBJECT_UPSTREAM;
        query_result.legacy_allowed = true; nkstat = 1;
        kstat_entries[0].target_ino = 43; kstat_entries[0].target_dev = new_encode_dev(MKDEV(8,7));
        kstat_entries[0].flags = KSTAT_SPOOF_INO; kstat_entries[0].spoofed_ino = 99;
        kstat_map_vma_entry(&instance,&regs); memcpy(buf,line,strlen(line)); m.count = strlen(line);
        expect(kstat_map_vma_ret(&instance,&regs) == 0 && maps_query_calls == 1 && legacy_lookup_calls == 1 &&
               legacy_gate_calls == (legacy ? 0U : 1U) && memmem_for_test(buf,m.count,"08:07 99"),
               "maps upstream and subject legacy table/gate behavior unchanged");
    }
}
static void test_legacy_writers_and_arming(void)
{
    struct st_susfs_sus_kstat info;
    unsigned int cmds[] = { CMD_SUSFS_ADD_SUS_KSTAT, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY,
                            CMD_SUSFS_UPDATE_SUS_KSTAT };
    grouped_active = true; register_calls = prepare_calls = release_calls = 0;
    kstat_maps_registered = kstat_maps_exiting = false; uid = 0;
    for (size_t i = 0; i < ARRAY_SIZE(cmds); i++) {
        reset(&info, sizeof(info), 0); memset(&info, 0, sizeof(info));
        strcpy(info.target_pathname, "/fixture"); info.err = 126;
        void *argument = &info;
        susfs_kstat_supercall(cmds[i], &argument);
        expect(info.err == -EBUSY && !nkstat && !prepare_calls && !register_calls && !kstat_lock.held,
               "every legacy supercall refuses grouped ownership before mutation or arming");
    }
    const char *commands[] = { "add_sus_kstat /fixture", "update_sus_kstat /fixture",
                              "update_sus_kstat_full_clone /fixture", "clear", "del /fixture",
                              "add_sus_kstat_statically /fixture 1 1 1 1 1 1 1 1 1 1 1 1" };
    for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
        char command[128]; reset(command, sizeof(command), 0); strcpy(command, commands[i]);
        expect(kstat_proc_write(NULL, command, strlen(command), NULL) == -EBUSY &&
               !nkstat && !prepare_calls && !register_calls && !kstat_lock.held,
               "every legacy proc mutation refuses grouped ownership");
    }
    grouped_active = false;
    reset(&info, sizeof(info), 0); memset(&info, 0, sizeof(info)); strcpy(info.target_pathname, "/fixture");
    void *argument = &info; susfs_kstat_supercall(CMD_SUSFS_ADD_SUS_KSTAT, &argument);
    expect(info.err == 0 && nkstat == 1 && prepare_calls == 1 && release_calls == 1 &&
           register_calls == 1 && kstat_maps_registered,
           "legacy mutation and optional maps arm still work in upstream mode");
    uid = 10000; char command[] = "clear"; user_start = (unsigned char *)command; user_length = sizeof(command);
    expect(kstat_proc_write(NULL, command, strlen(command), NULL) == -ENOENT && nkstat == 1,
           "forwarded root fd does not authorize non-root writes");
    grouped_active = true; kstat_maps_registered = false; register_calls = forget_calls = 0;
    register_error = -ENOENT; nkstat = 0;
    susfs_kstat_group_write_begin();
    expect(susfs_kstat_group_prepare_locked() == 0 && !kstat_maps_registered &&
           register_calls == 1 && forget_calls == 1 && !krp_kstat_map_vma.address,
           "first grouped preparation tries maps at zero legacy count and reports optional degradation");
    register_error = 0;
    expect(susfs_kstat_group_prepare_locked() == 0 && kstat_maps_registered && register_calls == 2,
           "later preparation retries and arms optional maps probe");
    expect(susfs_kstat_group_prepare_locked() == 0 && register_calls == 2,
           "preparing an already armed probe does not register twice");
    susfs_kstat_group_write_end();
    memset(kstat_hooks, 0, sizeof(kstat_hooks));
    expect(susfs_kstat_group_routes() == (1U << 16), "maps route bit describes actual armed state");
    for (size_t i = 0; i < ARRAY_SIZE(kstat_hooks); i++) {
        kstat_hooks[i].installed = true;
        expect(susfs_kstat_group_routes() == ((1U << (i + 1)) - 1U) + (1U << 16),
               "route mask preserves each wrapper's individual installation result");
    }
    kstat_maps_exiting = true; kstat_maps_registered = false;
    susfs_kstat_group_write_begin();
    expect(susfs_kstat_group_prepare_locked() == -ESHUTDOWN && register_calls == 2,
           "teardown prevents grouped preparation from rearming probes");
    susfs_kstat_group_write_end();
}
static void seed_legacy_rule(void)
{
    memset(kstat_entries, 0, sizeof(kstat_entries)); nkstat = 1;
    strcpy(kstat_entries[0].target_pathname, "/fixture");
    kstat_entries[0].target_ino = 43; kstat_entries[0].target_dev = new_encode_dev(MKDEV(8, 7));
    kstat_entries[0].spoofed_ino = 999; kstat_entries[0].spoofed_dev = new_encode_dev(MKDEV(254, 75));
    kstat_entries[0].spoofed_size = 321; kstat_entries[0].flags = KSTAT_SPOOF_SIZE;
}
static void test_preparation_takeover_and_retarget(void)
{
    struct st_susfs_sus_kstat info;
    unsigned int cmds[] = { CMD_SUSFS_ADD_SUS_KSTAT, CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY,
                            CMD_SUSFS_UPDATE_SUS_KSTAT };
    kstat_maps_exiting = kstat_maps_registered = false; uid = 0;
    for (size_t i = 0; i < ARRAY_SIZE(cmds); i++) {
        reset(&info, sizeof(info), 0); memset(&info, 0, sizeof(info)); strcpy(info.target_pathname, "/fixture");
        seed_legacy_rule(); struct sus_kstat_entry before = kstat_entries[0];
        grouped_active = false; takeover_during_prepare = true;
        prepare_calls = release_calls = register_calls = 0;
        void *argument = &info; susfs_kstat_supercall(cmds[i], &argument);
        expect(info.err == -EBUSY && grouped_active && prepare_calls == 1 && release_calls == 1 &&
               nkstat == 1 && !memcmp(&before, &kstat_entries[0], sizeof(before)) && !register_calls,
               "group takeover during VFS preparation rejects every supercall commit and preserves legacy table");
    }
    const char *commands[] = { "add_sus_kstat /fixture", "update_sus_kstat /fixture",
                              "update_sus_kstat_full_clone /fixture",
                              "add_sus_kstat_statically /fixture 1 1 1 1 1 1 1 1 1 1 1 1" };
    for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
        char command[128]; reset(command, sizeof(command), 0); strcpy(command, commands[i]);
        seed_legacy_rule(); struct sus_kstat_entry before = kstat_entries[0];
        grouped_active = false; takeover_during_prepare = true;
        prepare_calls = release_calls = register_calls = 0;
        expect(kstat_proc_write(NULL, command, strlen(command), NULL) == -EBUSY &&
               grouped_active && prepare_calls == 1 && release_calls == 1 && nkstat == 1 &&
               !memcmp(&before, &kstat_entries[0], sizeof(before)) && !register_calls,
               "group takeover during VFS preparation rejects every proc commit");
    }
    grouped_active = true;
    expect(susfs_kstat_del("/fixture") == -EBUSY && susfs_kstat_clear_legacy() == -EBUSY && nkstat == 1,
           "pure delete and clear commits independently recheck grouped ownership");
    grouped_active = false; seed_legacy_rule(); remove_during_prepare = true;
    expect(susfs_kstat_update("/fixture", false) == -ENOENT && nkstat == 0,
           "concurrent removal during resolution cannot reuse a borrowed stale table slot or report success");
    seed_legacy_rule(); fixture_inode.i_ino = 44;
    expect(susfs_kstat_update("/fixture", true) == 0 && kstat_entries[0].target_ino == 44 &&
           kstat_entries[0].spoofed_ino == 999 && kstat_entries[0].spoofed_size == 321 &&
           kstat_entries[0].flags == (KSTAT_SPOOF_SIZE | KSTAT_AUTO_SPOOF_FULL_CLONE),
           "retarget publishes resolved key atomically while retaining existing spoof values and full-clone flags");
    fixture_inode.i_ino = 43;
    struct sus_kstat_entry before = kstat_entries[0]; prepare_error = -ENOENT;
    expect(susfs_kstat_add("/fixture") == -ENOENT && nkstat == 1 &&
           !memcmp(&before, &kstat_entries[0], sizeof(before)), "failed VFS preparation keeps old table unchanged");
    prepare_error = 0;
}
int main(void)
{
    test_native(); test_compat(); test_statx(); test_content_size_views(); test_content_fd_classification(); test_maps(); test_all_authoritative_misses(); test_maps_redirect_priority();
    test_legacy_writers_and_arming(); test_preparation_takeover_and_retarget();
    printf("KSTAT_HOOK_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n", checks);
    return 0;
}
'''

SEARCH_DOUBLE = r'''
static bool memmem_for_test(const char *buffer, size_t count, const char *needle)
{
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= count; i++) if (!memcmp(buffer + i, needle, n)) return true;
    return false;
}
'''


def definition(source: str, name: str, structure: bool = False) -> str:
    if structure:
        return extract(source, name, structure=True)
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = rf"^(?:static\s+)?(?:bool|int|void|u32|ssize_t|struct\s+sus_kstat_entry\s*\*)\s*{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, flags=re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production definition for {name}, got {len(matches)}")
    start, depth = matches[0].start(), 0
    for cursor in range(masked.index("{", start), len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            return source[start:cursor + 1]
    raise ValueError(f"unbalanced production definition {name}")


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
    source_path = repo / "kernel/susfs_kstat.c"
    source = source_path.read_text(encoding="utf-8")
    structs = ["sus_kstat_entry", "sus_kstat_snapshot", "kstat_call_counters",
               "kstat_call_state", "susfs_statx_offs", "kstat_map_args"]
    names = ["kstat_snapshot", "susfs_kstat_lookup", "susfs_kstat_query_mode", "susfs_kstat_query", "susfs_kstat_maps_query", "susfs_kstat_query_call", "kstat_content_fd_query", "kstat_compat_narrow",
             "susfs_kstat_spoof_statbuf", "susfs_kstat_spoof_compat_statbuf",
             "susfs_kstat_spoof_compat_stat", "susfs_kstat_spoof_statx",
             "kstat_buf_replace", "kstat_map_vma_entry", "kstat_map_vma_ret",
             "kstat_maps_arm", "susfs_kstat_group_write_begin", "susfs_kstat_group_write_end",
             "susfs_kstat_group_prepare_locked", "susfs_kstat_group_routes", "split_ws",
             "susfs_kstat_find_by_path", "kstat_table_append", "kstat_table_put", "kstat_table_retarget",
             "kstat_table_del", "kstat_table_clear", "kstat_legacy_write_check", "kstat_legacy_commit",
             "susfs_kstat_resolve", "susfs_kstat_fill_from_path", "susfs_kstat_update", "susfs_kstat_add",
             "susfs_kstat_del", "susfs_kstat_clear_legacy", "parse_override",
             "susfs_kstat_add_statically", "susfs_kstat_add_statically_abi",
             "susfs_kstat_supercall", "kstat_proc_write"]
    pieces = {name: definition(source, name, structure=True) for name in structs}
    pieces.update({name: definition(source, name) for name in names})
    abi = (repo / "kernel/susfs_abi.h").read_text(encoding="utf-8")
    constants = re.findall(r"^#define KSTAT_SPOOF_[^\n]+", abi, flags=re.M)
    constants += re.findall(r"^#define (?:SUS_KSTAT_MAX|KSTAT_PATH_MAX|ST_[A-Z_]+|STAT64_[A-Z_]+|COMPAT_STAT_ST_[A-Z_]+|STATX_F_[A-Z_]+)[ \t]+[^\n]+",
                            source, flags=re.M)
    constants += re.findall(r"^#define COMPAT_[A-Z0-9_]+_NR[ \t]+[^\n]+", source, flags=re.M)
    constants.append(source[source.index("#define KSTAT_AUTO_SPOOF ("):source.index("#define SUS_KSTAT_MAX")])
    macros = source[source.index("#define STATX_FIELD_U64"):source.index("/* returns true when the buffer was really changed */")]
    offsets = re.search(r"^static const struct susfs_statx_offs kstat_statx_offs = \{.*?^\};", source, flags=re.M | re.S)
    if not offsets:
        raise ValueError("statx offset initializer missing")
    # timespec64's seconds/nanosecond offset equals the fixed statx timestamp.
    asserts = re.findall(r'^static_assert\([^\n]*struct compat_stat[^\n]*', source, flags=re.M)
    preamble = PREAMBLE + "\n" + "\n".join(asserts) + "\n"
    generated = evidence / "kstat-hook-regression-extracted.c"
    generated.write_text(preamble + "\n" + "\n".join(constants) + "\n" +
                         "\n".join(pieces[name] for name in structs) + "\n" + DOUBLES + "\n" +
                         offsets.group() + "\n" + macros + "\n" +
                         "\n\n".join(pieces[name] for name in names) + "\n" + SEARCH_DOUBLE + TESTS,
                         encoding="utf-8")
    receipt = {"production_source": "kernel/susfs_kstat.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(piece.encode()).hexdigest()
                                    for name, piece in pieces.items()},
               "limits": "Typed host doubles; not whole-TU/kernel RCU/VFS/userfault/probe/device validation.",
               "runs": []}
    for label, flags in [("strict", ["-O2"]),
                         ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("kstat-hook-regression-" + label + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-pedantic"] + flags
        command += ["-I", execution_path(repo / "kernel"), execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"KSTAT_HOOK_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "kstat-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
