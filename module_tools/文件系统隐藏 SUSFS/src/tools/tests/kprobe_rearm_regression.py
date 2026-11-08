#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the production rearm helpers with actual pinned-kernel lifecycle code.

Extracts register_kprobe, __disable_kprobe, unregister_kprobes and supporting
predicates/top/bottom functions from a supplied Linux source tree. Architecture,
locking, symbol resolution and allocation are host doubles. The embedded kprobe
of a kretprobe uses the same lifecycle; return-instance allocation is not tested.
This is a host regression, not an installed-module or device-effect test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from path_hook_regression import execute, execution_path


def extract(source: str, name: str) -> str:
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                    lambda match: ' ' * len(match.group()), source, flags=re.S)
    matches = list(re.finditer(
        rf'^(?:static\s+)?(?:inline\s+)?(?:int|bool|void|struct\s+kprobe\s*\*)\s*'
        rf'{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{', masked, re.M))
    if len(matches) != 1:
        raise ValueError(f'{name}: expected one function, found {len(matches)}')
    start = matches[0].start()
    depth = 0
    for cursor in range(masked.index('{', start), len(masked)):
        depth += (masked[cursor] == '{') - (masked[cursor] == '}')
        if not depth:
            return source[start:cursor + 1] + '\n'
    raise ValueError(f'{name}: unbalanced function')


DOUBLES = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
typedef unsigned int kprobe_opcode_t;
struct list_head { struct list_head *next, *prev; };
struct hlist_node { bool linked; };
struct hlist_head { int unused; };
struct module { int unused; };
struct kprobe {
    kprobe_opcode_t *addr;
    const char *symbol_name;
    unsigned long offset, flags, nmissed;
    struct list_head list;
    struct hlist_node hlist;
    void *post_handler;
};
struct kretprobe { struct kprobe kp; };
static int kprobe_mutex, text_mutex, fail_check;
static unsigned int hits, bottom_calls, checks;
static bool kprobes_all_disarmed, armed;
static kprobe_opcode_t instruction;
static struct hlist_head kprobe_table[1];
#define KPROBE_HASH_BITS 0
#define kprobe_disarmed(p) kprobe_disabled(p)
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define unlikely(x) (x)
#define INIT_LIST_HEAD(p) ((p)->next = (p)->prev = (p))
#define INIT_HLIST_NODE(p) ((p)->linked = false)
#define list_entry(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define list_for_each_entry(p,h,m) for ((p)=list_entry((h)->next,__typeof__(*(p)),m); &(p)->m!=(h); (p)=list_entry((p)->m.next,__typeof__(*(p)),m))
#define WARN_ON(x) assert(!(x))
static void mutex_lock(int *p) { (void)p; }
static void mutex_unlock(int *p) { (void)p; }
static void lockdep_assert_held(int *p) { (void)p; }
static void cpus_read_lock(void) {}
static void cpus_read_unlock(void) {}
static void synchronize_rcu(void) {}
static unsigned hash_ptr(const void *p, int bits) { (void)p; (void)bits; return 0; }
static void module_put(struct module *p) { (void)p; }
static void hlist_add_head_rcu(struct hlist_node *p, struct hlist_head *h) { (void)h; p->linked=true; }
static void hlist_del_rcu(struct hlist_node *p) { p->linked=false; }
static bool list_empty(struct list_head *p) { return p->next==p; }
static bool list_is_singular(struct list_head *p) { return !list_empty(p) && p->next==p->prev; }
static void list_del(struct list_head *p) { p->prev->next=p->next; p->next->prev=p->prev; }
static void list_del_rcu(struct list_head *p) { list_del(p); }
static bool kprobe_aggrprobe(struct kprobe *p) { (void)p; return false; }
static bool kprobe_ftrace(struct kprobe *p) { (void)p; return false; }
static void optimize_kprobe(struct kprobe *p) { (void)p; }
static void try_to_optimize_kprobe(struct kprobe *p) { (void)p; }
static void free_aggr_kprobe(struct kprobe *p) { (void)p; assert(false); }
static int prepare_kprobe(struct kprobe *p) { (void)p; return 0; }
static int arm_kprobe(struct kprobe *p) { (void)p; armed=true; return 0; }
static int disarm_kprobe(struct kprobe *p, bool force) { (void)p; (void)force; armed=false; return 0; }
static void arch_remove_kprobe(struct kprobe *p) { assert(p->addr); bottom_calls++; }
static struct kprobe *get_kprobe(void *addr) { (void)addr; return NULL; }
static struct kprobe *__get_valid_kprobe(struct kprobe *p) { return p->hlist.linked ? p : NULL; }
static int register_aggr_kprobe(struct kprobe *old, struct kprobe *p) { (void)old; (void)p; assert(false); return -EINVAL; }
static int warn_kprobe_rereg(struct kprobe *p) { return p->hlist.linked ? -EINVAL : 0; }
static int check_kprobe_address_safe(struct kprobe *p, struct module **m) { (void)p; *m=NULL; return fail_check; }
static kprobe_opcode_t *_kprobe_addr(kprobe_opcode_t *addr, const char *name, unsigned long offset, bool *entry)
{
    (void)offset; *entry=false;
    if ((name && addr) || (!name && !addr)) return ERR_PTR(-EINVAL);
    return addr ? addr : &instruction;
}
'''


TESTS = r'''
static void check(bool ok) { checks++; assert(ok); }
static void trigger(void) { if (armed) hits++; }
static void unregister_fixture(struct kprobe *p)
{
    struct kprobe *probes[]={p};
    unregister_kprobes(probes, 1);
}
static void forget(struct kretprobe *p, bool retprobe)
{
    if (retprobe) susfs_krp_forget_addr(p);
    else susfs_kp_forget_addr(&p->kp);
}
static unsigned failures;
static void cycle(bool retprobe, bool direct)
{
    struct kretprobe p={0};
    p.kp.symbol_name=direct ? NULL : "fixture_symbol";
    if (direct) p.kp.addr=&instruction;
    check(register_kprobe(&p.kp)==0);
    hits=0; trigger(); check(hits==1);
    unsigned first=hits;
    unregister_fixture(&p.kp);
    check(p.kp.addr!=NULL && (p.kp.flags & KPROBE_FLAG_DISABLED));
    check(!armed);
    unsigned before=bottom_calls;
    p.kp.flags|=KPROBE_FLAG_GONE;
    forget(&p,retprobe);
    check(!p.kp.addr && (p.kp.flags & KPROBE_FLAG_GONE));
    if (direct) p.kp.addr=&instruction;
    int rc=register_kprobe(&p.kp);
    check(rc==0);
    trigger(); unsigned second=hits-first;
    unregister_fixture(&p.kp);
    check(bottom_calls==before+1);
    forget(&p,retprobe);
    printf("%s %s first_hits=%u second_rc=%d second_hits=%u bottom_cleanup=complete\n",
           retprobe?"kretprobe":"kprobe",direct?"address":"symbol",first,rc,second);
    if (second!=1) failures++;
}
static void failed_retry(bool retprobe)
{
    struct kretprobe p={0}; p.kp.symbol_name="fixture_symbol";
    p.kp.flags=KPROBE_FLAG_DISABLED|KPROBE_FLAG_GONE;
    fail_check=-EACCES;
    check(register_kprobe(&p.kp)==-EACCES);
    check(p.kp.addr!=NULL);
    forget(&p,retprobe);
    check(!p.kp.addr);
    fail_check=0; hits=0;
    int rc=register_kprobe(&p.kp); check(rc==0); trigger();
    unsigned retried=hits;
    unregister_fixture(&p.kp); forget(&p,retprobe);
    printf("%s failed_registration_retry_rc=%d retry_hits=%u\n",retprobe?"kretprobe":"kprobe",rc,retried);
    if (retried!=1) failures++;
}
int main(void)
{
    cycle(false,false); cycle(false,true); cycle(true,false); cycle(true,true);
    failed_retry(false); failed_retry(true);
    printf("KPROBE_REARM cases=6 checks=%u failures=%u kernel_calls=false\n",checks,failures);
    return failures ? 1 : 0;
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-source', type=Path, required=True)
    parser.add_argument('--header', type=Path, default=Path(__file__).resolve().parents[2] / 'kernel/susfs_kprobe.h')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = args.kernel_source / 'kernel/kprobes.c'
    kernel_header_path = args.kernel_source / 'include/linux/kprobes.h'
    source = source_path.read_text(encoding='utf-8')
    kernel_header = kernel_header_path.read_text(encoding='utf-8')
    header = args.header.read_text(encoding='utf-8')
    functions = {name: extract(kernel_header if name in ('kprobe_disabled', 'kprobe_gone') else source, name)
                 for name in ('kprobe_disabled', 'kprobe_gone', 'register_kprobe', 'aggr_kprobe_disabled',
                              '__disable_kprobe', '__unregister_kprobe_top', '__unregister_kprobe_bottom',
                              'unregister_kprobes')}
    constants = []
    for name in ('KPROBE_FLAG_DISABLED', 'KPROBE_FLAG_GONE', 'KPROBE_FLAG_ON_FUNC_ENTRY'):
        matches = re.findall(rf'^#define\s+{name}\s+\d+', kernel_header, flags=re.M)
        if len(matches) != 1:
            raise ValueError(f'expected one {name}')
        constants += matches
    header = re.sub(r'^#include[^\n]*\n', '', header, flags=re.M)
    generated = evidence / 'kprobe-rearm.c'
    generated.write_text(DOUBLES + '\n'.join(constants) + '\n' + '\n'.join(functions.values()) +
                         '\n' + header + '\n' + TESTS, encoding='utf-8')
    binary = evidence / 'kprobe-rearm.bin'
    command = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2',
               execution_path(generated), '-o', execution_path(binary)]
    build = execute(command)
    (evidence / 'build.stdout.txt').write_text(build.stdout, encoding='utf-8')
    (evidence / 'build.stderr.txt').write_text(build.stderr, encoding='utf-8')
    receipt = {'kernel_calls': False, 'limits': __doc__, 'compile_command': command,
               'compile_exit': build.returncode,
               'inputs': {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (source_path, kernel_header_path, args.header)},
               'extracted_functions': {name: hashlib.sha256(text.encode()).hexdigest()
                                       for name, text in functions.items()}, 'passed': False}
    if not build.returncode:
        run = execute([execution_path(binary)])
        receipt.update(run_command=[execution_path(binary)], run_exit=run.returncode,
                       stdout=run.stdout, stderr=run.stderr,
                       passed=run.returncode==0 and not run.stderr)
        (evidence / 'stdout.txt').write_text(run.stdout, encoding='utf-8')
        (evidence / 'stderr.txt').write_text(run.stderr, encoding='utf-8')
        print(run.stdout, end='')
    else:
        print(build.stderr, end='')
    (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
