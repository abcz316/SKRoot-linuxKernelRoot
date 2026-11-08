#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check d_path tail placement using the exact production entry/return handlers.

Only patterned host memory and typed call-boundary doubles are used. This focused
regression does not establish real procfs, kernel probes, RCU or device behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from path_hook_regression import execution_path, extract


PREAMBLE = r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
struct inode { unsigned int fixture; };
struct dentry { struct inode *inode; };
struct path { struct dentry *dentry; };
struct pt_regs { unsigned long regs[31]; };
struct kretprobe_instance { void *data; };
struct skp_redirect_query_result { char path[256]; };
static struct skp_redirect_query_result answer;
static bool answer_matches = true;
static unsigned int or_rev_dpath_hits, checks, cases, copies;
static struct inode *d_backing_inode(struct dentry *d) { return d->inode; }
static bool or_reverse_lookup(struct inode *inode, struct skp_redirect_query_result *result)
{ (void)inode; *result = answer; return answer_matches; }
static void atomic_inc(unsigned int *value) { ++*value; }
static long strscpy(char *dst, const char *src, size_t capacity)
{
 size_t len = strlen(src);
 if (!capacity) return -E2BIG;
 if (len >= capacity) { memcpy(dst, src, capacity - 1); dst[capacity - 1] = 0; return -E2BIG; }
 memcpy(dst, src, len + 1); return (long)len;
}
static void expect(bool condition, const char *message)
{ ++checks; if (!condition) { fprintf(stderr, "FAIL case=%u check=%u %s\n", cases, checks, message); exit(1); } }
'''

TESTS = r'''
#define GUARD 32
#define MAXBUF 4096
#define MAXREAD 4095
static void fill_target(char *target, size_t len)
{
 expect(len > 0 && len < OR_PATH_MAX, "fixture target fits captured path");
 for (size_t i = 0; i < len; ++i) target[i] = i ? (char)('a' + i % 26) : '/';
 target[len] = 0;
}
static void check_case(int buflen, size_t len, int error)
{
 unsigned char area[MAXBUF + 2 * GUARD], before[sizeof(area)];
 char *buf = (char *)area + GUARD;
 struct or_dpath_args captured = { .buf = buf, .buflen = buflen };
 struct kretprobe_instance ri = { .data = &captured };
 struct pt_regs regs = { { 0 } };
 const char native[] = "/fixture/native";
 char *native_ret = buf;
 ++cases; memset(area, 0xa5, sizeof(area));
 if (buflen >= (int)sizeof(native)) {
  native_ret = buf + buflen - sizeof(native); memcpy(native_ret, native, sizeof(native));
 }
 fill_target(captured.target, len);
 if (error) native_ret = (char *)(intptr_t)-error;
 regs.regs[0] = (unsigned long)native_ret; memcpy(before, area, sizeof(area));
 expect(or_dpath_ret(&ri, &regs) == 0, "return handler preserves probe status");
 if (error || buflen <= 0 || len >= (size_t)buflen) {
  expect(regs.regs[0] == (unsigned long)native_ret, "error/too-small result pointer preserved");
  expect(!memcmp(area, before, sizeof(area)), "error/too-small buffer unchanged"); return;
 }
 const size_t offset = (size_t)buflen - len - 1;
 char *result = (char *)regs.regs[0];
 expect(result == buf + offset, "result points to exact tail-placed path");
 expect(result[len] == 0 && buf[buflen - 1] == 0, "terminator is last buffer byte");
 expect(!memcmp(result, captured.target, len + 1), "complete captured target copied");
 expect(!memcmp(area, before, GUARD + offset), "prefix and leading canary unchanged");
 expect(!memcmp(area + GUARD + buflen, before + GUARD + buflen, sizeof(area) - GUARD - (size_t)buflen), "trailing buffer canary unchanged");
 const size_t derived = (size_t)((buf + buflen - 1) - result);
 expect(derived == len, "proc consumer end-minus-pointer equals path length");
 expect(!memchr(result, 0, derived), "consumer return interval has no NUL");
 const size_t requests[] = { 1, 7, len - 1, len, len + 1, MAXREAD };
 for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
  if (!requests[i]) continue;
  unsigned char user[MAXREAD + 2 * GUARD];
  const size_t count = requests[i] < derived ? requests[i] : derived;
  memset(user, 0xcc, sizeof(user));
  memcpy(user + GUARD, result, count); ++copies;
  expect(count == (requests[i] < len ? requests[i] : len), "readlink copy returns min(requested,path length)");
  expect(!memcmp(user + GUARD, captured.target, count), "readlink copy contains only target bytes");
  expect(!memchr(user + GUARD, 0, count), "readlink result excludes terminating NUL");
  for (size_t j = 0; j < GUARD; ++j) expect(user[j] == 0xcc, "user leading canary unchanged");
  for (size_t j = GUARD + count; j < sizeof(user); ++j) expect(user[j] == 0xcc, "user bytes beyond reported count unchanged");
 }
}
static void snapshot_and_gates(void)
{
 char buf[128], before[sizeof(buf)];
 struct inode inode = { 1 }; struct dentry dentry = { &inode }; struct path path = { &dentry };
 struct or_dpath_args captured = { 0 }; struct kretprobe_instance ri = { .data = &captured };
 struct pt_regs regs = { { (unsigned long)&path, (unsigned long)buf, sizeof(buf) } };
 ++cases; strcpy(answer.path, "/captured/source"); answer_matches = true;
 expect(or_dpath_entry(&ri, &regs) == 0 && or_rev_dpath_hits == 1, "real entry captures lookup snapshot");
 strcpy(answer.path, "/later/configuration");
 memset(buf, 0x5a, sizeof(buf)); regs.regs[0] = (unsigned long)(buf + 7);
 or_dpath_ret(&ri, &regs);
 expect(!strcmp((char *)regs.regs[0], "/captured/source"), "entry snapshot survives later config mutation");
 expect((char *)regs.regs[0] == buf + sizeof(buf) - sizeof("/captured/source"), "captured snapshot obeys tail contract");
 const unsigned long original = (unsigned long)(buf + 7);
 memset(buf, 0x5a, sizeof(buf)); memcpy(before, buf, sizeof(buf));
 captured.target[0] = 0; regs.regs[0] = original; or_dpath_ret(&ri, &regs);
 expect(regs.regs[0] == original && !memcmp(buf, before, sizeof(buf)), "empty capture is no-op");
 strcpy(captured.target, "/source"); captured.buf = NULL; or_dpath_ret(&ri, &regs);
 expect(regs.regs[0] == original && !memcmp(buf, before, sizeof(buf)), "null buffer is no-op");
 captured.buf = buf; answer_matches = false; regs.regs[0] = (unsigned long)&path;
 or_dpath_entry(&ri, &regs); expect(!captured.target[0], "lookup miss clears stale capture");
 regs.regs[0] = original; or_dpath_ret(&ri, &regs);
 expect(regs.regs[0] == original && !memcmp(buf, before, sizeof(buf)), "lookup miss keeps native result");
}
int main(void)
{
 const size_t lengths[] = { 1, 7, 58, OR_PATH_MAX - 1 };
 for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
  const size_t len = lengths[i];
  for (int capacity = -1; capacity <= 512; ++capacity) check_case(capacity, len, 0);
  check_case(4095, len, 0); check_case(4096, len, 0);
  check_case((int)len + 1, len, ENOENT); check_case(4096, len, ENAMETOOLONG);
  check_case(4096, len, EACCES);
 }
 snapshot_and_gates();
 printf("READLINK_TAIL_REGRESSION checks=%u cases=%u copies=%u passed=true kernel_calls=false extracted_production=true\n", checks, cases, copies);
 return 0;
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--wsl-distro")
    parser.add_argument("--source", type=Path, help="Optional saved production source for negative control")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    source_path = (args.source or repo / "kernel/susfs_open_redirect.c").resolve()
    source = source_path.read_text(encoding="utf-8")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    pieces = {"or_dpath_args": extract(source, "or_dpath_args", structure=True)}
    pieces.update({name: extract(source, name) for name in ("or_dpath_entry", "or_dpath_ret")})
    constants = re.findall(r"^#define OR_PATH_MAX [^\n]+", source, flags=re.M)
    if len(constants) != 1:
        raise ValueError("expected one production OR_PATH_MAX")
    generated = evidence / "readlink-tail-extracted.c"
    generated.write_text(PREAMBLE + "\n" + constants[0] + "\n" + "\n\n".join(pieces.values()) + TESTS, encoding="utf-8")
    prefix = (["wsl"] + (["--distribution", args.wsl_distro] if args.wsl_distro else []) + ["--exec"]) if os.name == "nt" else []

    def execute(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(prefix + command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)

    receipt = {"production_source": str(source_path), "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(piece.encode()).hexdigest() for name, piece in pieces.items()},
               "kernel_calls": False, "device_calls": False,
               "limits": "Exact production entry/return handlers with typed host doubles and patterned memory; no kernel/procfs/probe/RCU/device proof.",
               "runs": []}
    for name, flags in [("strict", ["-O2"]),
                        ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("readlink-tail-" + name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"] + flags + [execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (name + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
        (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": name, "build_command": prefix + command, "build_exit": build.returncode, "passed": False}
        if build.returncode == 0:
            run_command = ["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)]
            run = execute(run_command)
            (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"READLINK_TAIL_REGRESSION checks=(\d+) cases=(\d+) copies=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_command=prefix + run_command, run_exit=run.returncode, checks=int(match[1]) if match else 0,
                          cases=int(match[2]) if match else 0, copies=int(match[3]) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(record["passed"] for record in receipt["runs"])
    path = evidence / "readlink-tail-receipt.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(path), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
