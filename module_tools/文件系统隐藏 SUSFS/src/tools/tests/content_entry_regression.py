#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the production open entry's content integration with typed doubles.

Production declarations and function bodies are extracted without rewriting.
This checks argument preservation, publication order and cleanup; it does not
establish actual VFS/LSM/CFI, descriptor sharing or Android device behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from kstat_hook_regression import execute
from path_hook_regression import execution_path, extract


PREAMBLE = r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#define READ_ONCE(x) (x)
#include "susfs_or_entry.h"
typedef unsigned short umode_t;
#define __nocfi
#define noinline
#define __user
#define __aarch64__ 1
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE TEST_KERNEL_VERSION
#define SUSFS_OR_PATH_MAX 256
#define S_IALLUGO 07777
#define FMODE_NONOTIFY (1U << 26)
#ifndef __O_SYNC
#define __O_SYNC (O_SYNC & ~O_DSYNC)
#endif
#ifndef FASYNC
#define FASYNC O_ASYNC
#endif
#undef O_LARGEFILE
#define O_LARGEFILE 00100000
#define LOOKUP_FOLLOW 1U
#define LOOKUP_DIRECTORY 2U
#define LOOKUP_NO_XDEV 4U
#define LOOKUP_NO_MAGICLINKS 8U
#define LOOKUP_NO_SYMLINKS 16U
#define LOOKUP_BENEATH 32U
#define LOOKUP_IN_ROOT 64U
#define LOOKUP_CACHED 128U
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define PTR_ERR(p) ((long)(intptr_t)(p))
struct pt_regs { unsigned long regs[8]; };
struct filename { char *name; };
struct path { unsigned int identity; };
struct susfs_content { unsigned int refs; };
struct file { bool bound; bool path_redirect; unsigned long flags; };
typedef struct { unsigned int value; } atomic_t;
static void atomic_inc(atomic_t *counter) { counter->value++; }
static bool or_entry_ready=true;
static atomic_t or_entry_hits;
static unsigned int checks,names,paths,reserved,installed,content_opens,path_opens;
static unsigned int getnames,lookups,matches,notifications;
static unsigned int expected_dfd,allocation_flags;
static unsigned long opened_flags,opened_mode,opened_resolve;
static bool active=true,content_applies=true,path_applies,fail_name,fail_lookup;
static bool fail_copy,fail_fd,fail_content_open,fail_path_open;
static struct susfs_content fixture={1};
static struct file *published;
static char trace[128];
static const char *const source_name="cpuinfo";
static void expect(bool condition,const char *message)
{
 ++checks;
 if(!condition){fprintf(stderr,"FAIL check=%u %s trace=%s\n",checks,message,trace);exit(1);}
}
static void event(char value)
{ size_t n=strlen(trace);expect(n+1<sizeof(trace),"trace fits");trace[n]=value;trace[n+1]=0; }
static bool susfs_open_redirect_active(void) { return active; }
static int copy_from_user(void *out,const void *input,size_t size)
{ if(fail_copy)return 1;memcpy(out,input,size);return 0; }
static struct filename *test_getname(const char *name,int flags,int *empty)
{
 (void)empty;getnames++;expect(flags==0,"getname flags retained");
 if(fail_name)return ERR_PTR(-EFAULT);
 struct filename *result=malloc(sizeof(*result));expect(result!=NULL,"allocate name");
 result->name=strdup(name);expect(result->name!=NULL,"copy original filename");names++;event('N');return result;
}
static int test_lookup(int dfd,struct filename *name,unsigned int flags,struct path *path,struct path *root)
{
 lookups++;expect((unsigned int)dfd==expected_dfd,"lookup keeps original dirfd");
 expect(name&&names==1&&!strcmp(name->name,source_name),"lookup keeps original filename");
 expect(root==NULL,"lookup root remains unset");(void)flags;
 if(fail_lookup)return -ENOENT;
 path->identity=41;paths++;event('L');return 0;
}
static void test_putname(struct filename *name)
{ expect(names==1&&name!=NULL,"name released once");names--;free(name->name);free(name);event('n'); }
static void path_put(struct path *path)
{ expect(paths==1&&path->identity==41,"matched source path released once");paths--;event('p'); }
static struct susfs_content *skp_policy_content_get(const struct path *path)
{
 expect(paths==1&&path->identity==41,"content lookup uses held source path");
 if(!content_applies)return NULL;
 fixture.refs++;event('C');return &fixture;
}
static void susfs_content_put(struct susfs_content *content)
{ expect(content==&fixture&&fixture.refs>1,"owned content reference released");fixture.refs--;event('c'); }
static int test_alloc_fd(unsigned int flags)
{
 expect(!reserved&&!installed,"allocate one unpublished descriptor");
 allocation_flags=flags;if(fail_fd)return -EMFILE;
 reserved=1;event('D');return 17;
}
static void test_put_fd(unsigned int fd)
{ expect(fd==17&&reserved==1&&!installed,"failed unpublished fd released once");reserved=0;event('d'); }
static struct file *susfs_content_open(int dfd,struct filename *name,unsigned long flags,
 unsigned long mode,unsigned long resolve,const struct path *path,struct susfs_content *content)
{
 content_opens++;event('A');
 expect(reserved==1&&!installed,"full A open occurs before descriptor publication");
 expect((unsigned int)dfd==expected_dfd&&names==1&&!strcmp(name->name,source_name),"full A open preserves dirfd and copied filename");
 expect(paths==1&&path->identity==41&&content==&fixture&&fixture.refs==2,"full A open owns matched source and payload");
 opened_flags=flags;opened_mode=mode;opened_resolve=resolve;
 if(fail_content_open)return ERR_PTR(-EACCES);
 struct file *file=calloc(1,sizeof(*file));expect(file!=NULL,"allocate full A file");
 file->bound=true;file->flags=flags&~O_CLOEXEC;fixture.refs++;event('B');return file;
}
static bool susfs_open_redirect_match_path(const struct path *path,char *target,size_t size)
{
 matches++;expect(paths==1&&path->identity==41,"path mode sees held source identity");
 if(!path_applies)return false;
 expect(size>=sizeof("/target"),"path target fits");strcpy(target,"/target");return true;
}
static struct file *test_filp_open(const char *name,int flags,umode_t mode)
{
 path_opens++;expect(reserved==1&&!names&&!paths,"path mode retains old cleanup/open sequence");
 expect(!strcmp(name,"/target"),"path mode opens configured target");
 opened_flags=(unsigned int)flags;opened_mode=mode;
 if(fail_path_open)return ERR_PTR(-ENOENT);
 struct file *file=calloc(1,sizeof(*file));expect(file!=NULL,"allocate path-mode file");
 file->path_redirect=true;file->flags=flags;return file;
}
static void test_install(unsigned int fd,struct file *file)
{
 expect(fd==17&&reserved==1&&!installed&&file&&!IS_ERR(file),"install reserved valid fd once");
 expect(!names&&!paths,"source lookup references released before fd publication");
 expect(content_applies?file->bound:file->path_redirect,"file content binding finishes before fd_install");
 expect(!content_applies||fixture.refs==2,"installed content holds rule and FD refs only");
 reserved=0;installed=1;published=file;event('I');
}
static void test_notify(struct file *file)
{ expect(file&&!installed,"notification precedes publication");notifications++; }
static int test_zeroed(const void *source,unsigned long size)
{ const unsigned char *bytes=source;for(unsigned long i=0;i<size;i++)if(bytes[i])return 0;return 1; }
static struct filename *(*or_getname_flags_fn)(const char *,int,int *)=test_getname;
static int (*or_filename_lookup_fn)(int,struct filename *,unsigned int,struct path *,struct path *)=test_lookup;
static void (*or_putname_fn)(struct filename *)=test_putname;
static struct file *(*or_filp_open_fn)(const char *,int,umode_t)=test_filp_open;
static int (*or_get_unused_fd_flags_fn)(unsigned int)=test_alloc_fd;
static void (*or_fd_install_fn)(unsigned int,struct file *)=test_install;
static void (*or_put_unused_fd_fn)(unsigned int)=test_put_fd;
static void (*or_fsnotify_open_fn)(struct file *)=test_notify;
static int (*or_check_zeroed_user_fn)(const void *,unsigned long)=test_zeroed;
'''

TESTS = r'''
static void reset(void)
{
 expect(!names&&!paths&&!reserved&&!installed&&!published&&fixture.refs==1,"previous case released every owned reference");
 trace[0]=0;content_opens=path_opens=getnames=lookups=matches=notifications=allocation_flags=0;
 expected_dfd=19;opened_flags=opened_mode=opened_resolve=0;
 active=content_applies=true;path_applies=fail_name=fail_lookup=fail_copy=false;
 fail_fd=fail_content_open=fail_path_open=false;or_entry_ready=true;or_entry_hits.value=0;
}
static void close_published(void)
{
 expect(installed==1&&published!=NULL,"close valid published fixture fd");
 if(published->bound){expect(fixture.refs==2,"FD owns payload until close");fixture.refs--;}
 free(published);published=NULL;installed=0;
}
static long call_open(int kind,unsigned long flags,unsigned long mode)
{
 struct pt_regs regs={{0}};
 struct susfs_open_how how={flags,mode,SUSFS_RESOLVE_NO_MAGICLINKS};
 if(kind==SUSFS_OR_ENTRY_OPENAT2||kind==SUSFS_OR_ENTRY_COMPAT_OPENAT2){
  regs.regs[0]=expected_dfd;regs.regs[1]=(unsigned long)source_name;
  regs.regs[2]=(unsigned long)&how;regs.regs[3]=sizeof(how);
 }else if(kind==SUSFS_OR_ENTRY_COMPAT_OPEN){
  expected_dfd=(unsigned int)AT_FDCWD;regs.regs[0]=(unsigned long)source_name;
  regs.regs[1]=flags;regs.regs[2]=mode;
 }else{
  regs.regs[0]=expected_dfd;regs.regs[1]=(unsigned long)source_name;regs.regs[2]=flags;regs.regs[3]=mode;
 }
 return or_entry_redirect(&regs,kind);
}
static void content_success(void)
{
 const int kinds[]={SUSFS_OR_ENTRY_OPENAT,SUSFS_OR_ENTRY_COMPAT_OPEN,SUSFS_OR_ENTRY_COMPAT_OPENAT,
  SUSFS_OR_ENTRY_OPENAT2,SUSFS_OR_ENTRY_COMPAT_OPENAT2};
 for(size_t i=0;i<sizeof(kinds)/sizeof(kinds[0]);i++){
  reset();int kind=kinds[i];
  expect(call_open(kind,O_RDONLY|O_CLOEXEC,0)==17,"supported entry publishes content fd");
  expect(content_opens==1&&path_opens==0&&matches==0,"content never opens B via old path redirect");
  expect(allocation_flags==O_CLOEXEC,"CLOEXEC belongs to allocated descriptor");
  expect(!(published->flags&O_CLOEXEC),"CLOEXEC is absent from file flags");
  expect(opened_mode==0,"read-only full A open carries zero mode");
  expect(!!(opened_flags&O_LARGEFILE)==(kind!=SUSFS_OR_ENTRY_COMPAT_OPEN&&kind!=SUSFS_OR_ENTRY_COMPAT_OPENAT),"native largefile semantics preserved");
  expect(opened_resolve==((kind==SUSFS_OR_ENTRY_OPENAT2||kind==SUSFS_OR_ENTRY_COMPAT_OPENAT2)?SUSFS_RESOLVE_NO_MAGICLINKS:0),"openat2 resolution passed into full A open");
  expect(strchr(trace,'A')<strchr(trace,'B')&&strchr(trace,'B')<strchr(trace,'I'),"authorization and binding precede install");
  expect(or_entry_hits.value==1,"successful entry records one hit");
  expect(notifications==(TEST_KERNEL_VERSION<KERNEL_VERSION(6,6,0)?1U:0U),"notification matches kernel responsibility");
  close_published();
 }
 reset();expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,07777)==17,"legacy openat ignores extra mode when not creating");
 expect(opened_mode==0,"legacy unused mode zeroed before build_open_flags");close_published();
 reset();expect(call_open(SUSFS_OR_ENTRY_COMPAT_OPEN,O_RDONLY,0644)==17,"compat open ignores extra mode");
 expect(opened_mode==0,"compat unused mode zeroed");close_published();
 reset();expect(call_open(SUSFS_OR_ENTRY_OPENAT2,O_RDONLY,0644)==SUSFS_OR_ENTRY_PASS,"openat2 nonzero read-only mode remains invalid");
 expect(!getnames&&!content_opens&&!installed,"invalid openat2 mode never reaches content open");
}
static void failure_cleanup(void)
{
 reset();fail_name=true;expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==SUSFS_OR_ENTRY_PASS,"name fault delegates original error");
 expect(!names&&!paths&&!reserved&&fixture.refs==1,"name fault keeps no refs");
 reset();fail_lookup=true;expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==SUSFS_OR_ENTRY_PASS,"lookup failure delegates original error");
 expect(!names&&!paths&&!reserved&&fixture.refs==1,"lookup failure releases filename");
 reset();fail_fd=true;expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY|O_CLOEXEC,0)==-EMFILE,"fd exhaustion is returned");
 expect(!names&&!paths&&!reserved&&fixture.refs==1&&!content_opens,"fd exhaustion releases all lookup refs before full open");
 reset();fail_content_open=true;expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==-EACCES,"source authorization error returned");
 expect(!names&&!paths&&!reserved&&!installed&&fixture.refs==1,"failed full A open releases fd/name/path/content");
 expect(strchr(trace,'d')!=NULL&&!strchr(trace,'I'),"failed open never publishes reserved fd");
 reset();fail_copy=true;expect(call_open(SUSFS_OR_ENTRY_OPENAT2,O_RDONLY,0)==SUSFS_OR_ENTRY_PASS,"open_how user fault is delegated");
 expect(!getnames&&!content_opens&&fixture.refs==1,"open_how fault acquires no refs");
}
static void unchanged_path_mode(void)
{
 reset();content_applies=false;path_applies=true;
 expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY|O_CLOEXEC,0)==17,"ordinary path mode still redirects");
 expect(path_opens==1&&!content_opens&&matches==1&&fixture.refs==1,"ordinary path mode never acquires content ownership");
 expect(allocation_flags==O_CLOEXEC&&!(opened_flags&O_CLOEXEC),"ordinary path CLOEXEC behavior preserved");close_published();
 reset();content_applies=false;path_applies=true;fail_path_open=true;
 expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==-ENOENT,"ordinary target error unchanged");
 expect(!names&&!paths&&!reserved&&!installed&&fixture.refs==1,"ordinary path failure releases reserved fd");
 reset();content_applies=false;
 expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==SUSFS_OR_ENTRY_PASS,"unmatched ordinary open falls through");
 expect(matches==1&&!names&&!paths&&!reserved,"unmatched source lookup refs released");
}
static void path_only(void)
{
 reset();expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_PATH|O_CLOEXEC|O_CREAT|O_TRUNC,0777)==SUSFS_OR_ENTRY_PASS,"O_PATH falls through after legacy flag narrowing");
 expect(!content_opens&&!path_opens&&!reserved&&!installed&&fixture.refs==1&&!names&&!paths,"O_PATH never wraps or leaks refs");
 reset();expect(call_open(SUSFS_OR_ENTRY_OPENAT2,O_PATH|O_CLOEXEC,0)==SUSFS_OR_ENTRY_PASS,"valid openat2 O_PATH remains path-only");
 expect(!content_opens&&!reserved&&fixture.refs==1&&!names&&!paths,"openat2 O_PATH releases lookup references");
 reset();active=false;expect(call_open(SUSFS_OR_ENTRY_OPENAT,O_RDONLY,0)==SUSFS_OR_ENTRY_PASS,"empty rules bypass name layer");
 expect(!getnames&&!content_opens,"inactive path has no lookup overhead");
}
int main(void)
{
 content_success();failure_cleanup();unchanged_path_mode();path_only();reset();
 printf("CONTENT_ENTRY_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",checks);return 0;
}
'''


def definition(source: str, name: str) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = rf"^static\s+(?:__nocfi\s+)?(?:noinline\s+)?(?:long|int|void|unsigned\s+int)\s+{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production definition for {name}, got {len(matches)}")
    start, depth = matches[0].start(), 0
    for cursor in range(masked.index("{", start), len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if depth == 0:
            return source[start:cursor + 1]
    raise ValueError(f"unbalanced production definition {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    source_path = repo / "kernel/susfs_or_entry.c"
    source = source_path.read_text(encoding="utf-8")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    macro_start = source.index("#define SUSFS_OR_KNOWN_FLAGS")
    macro_end = source.index("/* The lookup flags", macro_start)
    pieces = {"flags_and_resolution": source[macro_start:macro_end],
              "susfs_open_how": extract(source, "susfs_open_how", structure=True)}
    for name in ["or_lookup_flags", "or_fsnotify_open", "or_check_zeroed_user", "or_put_unused_fd", "or_entry_redirect"]:
        pieces[name] = definition(source, name)
    generated = evidence / "content-entry-regression-extracted.c"
    # Only supply the kernel headers needed by susfs_or_entry.h through tiny
    # typed fixtures. The production enum and pass sentinel remain unchanged.
    includes = evidence / "include/linux"
    includes.mkdir(parents=True, exist_ok=True)
    (includes / "limits.h").write_text("#include <limits.h>\n", encoding="utf-8")
    (includes / "ptrace.h").write_text("struct pt_regs;\n", encoding="utf-8")
    generated.write_text(PREAMBLE + "\n" + "\n".join(pieces.values()) + "\n" + TESTS, encoding="utf-8")
    receipt = {"source": "kernel/susfs_or_entry.c", "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "extracted_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in pieces.items()},
               "limits": "Typed entry integration doubles; not actual VFS/LSM/CFI or device validation.", "runs": []}
    for version, label in [(0x060c00, "6.12"), (0x060600, "6.6"), (0x060100, "6.1")]:
        for flavor, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
            run_name = label + "-" + flavor
            binary = evidence / (run_name + ".bin")
            command = [args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                       f"-DTEST_KERNEL_VERSION={version}", *flags, "-I", execution_path(evidence / "include"),
                       "-I", execution_path(repo / "kernel"), execution_path(generated), "-o", execution_path(binary)]
            build = execute(command)
            (evidence / (run_name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
            record = {"name": run_name, "build_exit": build.returncode, "passed": False}
            if build.returncode == 0:
                run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
                (evidence / (run_name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
                (evidence / (run_name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
                match = re.search(r"CONTENT_ENTRY_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
                record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                              passed=run.returncode == 0 and match is not None and not run.stderr)
            receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "content-entry-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
