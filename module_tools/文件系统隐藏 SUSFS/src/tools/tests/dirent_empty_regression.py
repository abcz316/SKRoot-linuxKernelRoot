#!/usr/bin/env python3
"""Extract the real filter, listing post-check and syscall wrapper as one host test.

The original syscall and kernel objects are typed doubles. --source-root also
supports historical trees for identical before/after observations. No device
or real FUSE execution is implied.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re

from content_entry_regression import definition
from dirent_chain_regression import COMPACTION_PREAMBLE, COMPACTION_DOUBLES, COMPACTION_TESTS, filter_function
from path_hook_regression import extract, execution_path
from kstat_hook_regression import execute

SUPPORT = r'''
#include <sys/mman.h>
#define __nocfi
#define compat_ptr(v) ((void *)(uintptr_t)(v))
struct pt_regs { unsigned long regs[8]; };
typedef long (*susfs_syscall_fn_t)(const struct pt_regs *);
struct dentry { int identity; bool contents; };
struct inode { struct super_block *i_sb; };
struct path { struct dentry *dentry; };
struct file { struct inode *inode; struct path f_path; unsigned refs; };
struct susfs_dirent_call { bool active; };
struct test_task { int identity; };
static struct test_task task={1};
#define current (&task)
static struct dentry first_dentry={1,false},second_dentry={2,false};
static struct inode dir_inode={&original_sb};
static struct file first_file={&dir_inode,{&first_dentry},0},second_file={&dir_inode,{&second_dentry},0};
static struct file *fd_file,*held_file;
static const char *chunks[4][3];
static unsigned chunk_count,stream_calls,acquires,releases,reschedules,alternate_gets;
static unsigned hidden_batches;
static long terminal_error;
static bool pending_signal,scrub_fault,swap_fd,mutate_regs,exempt;
static unsigned char *storage,*buffer;
static size_t last_count;
static int layout_id;
static struct pt_regs input;
static void syscall_get_arguments(struct test_task *t,struct pt_regs *r,unsigned long *a)
{ expect(t==current,"original task used");memcpy(a,r->regs,6*sizeof(*a)); }
static struct file *susfs_dirent_file_get(unsigned int fd)
{
 expect(fd==11,"original FD argument retained on retry");acquires++;fd_file->refs++;held_file=fd_file;
 if(fd_file==&second_file)alternate_gets++;
 return fd_file;
}
static struct inode *file_inode(struct file *f)
{ expect(f->refs==1,"postfilter uses held file");return f->inode; }
static void fput(struct file *f)
{ expect(f->refs==1,"release only owned reference");f->refs--;releases++; }
static bool susfs_dirent_begin(struct susfs_dirent_call *c,struct file *f,bool compat)
{ (void)compat;expect(f->refs==1,"composition begins with held file");c->active=true;return false; }
static bool susfs_dirent_end(struct susfs_dirent_call *c)
{ expect(c->active,"composition ended once per original call");c->active=false;return false; }
static bool skp_policy_path_contents_hidden(const struct dentry *d,bool self)
{ expect(self&&d==held_file->f_path.dentry,"postfilter uses this batch's captured directory");return d->contents; }
static bool signal_pending(struct test_task *t)
{ expect(t==current,"signal check uses current task");return pending_signal; }
static void cond_resched(void) { reschedules++; }
static long prior_syscall(const struct pt_regs *r)
{
 for(unsigned i=0;i<6;i++)expect(r->regs[i]==input.regs[i],"all original arguments retained for each read");
 unsigned index=stream_calls++;
 const struct sus_dirent_layout *lay=layout_id==SUS_DIRENT_COMPAT?&sus_dirent_compat:&sus_dirent_l64;
 if(index>=(hidden_batches?hidden_batches:chunk_count))return terminal_error;
 memset(storage,0xa5,8192);last_count=0;
 if(hidden_batches)last_count=record_append(buffer,0,lay,101,"ab");
 else for(unsigned n=0;n<3&&chunks[index][n];n++){
  /* This represents the prior SKP chain: its private entry never reaches SUSFS. */
  if(!strcmp(chunks[index][n],"skp-private-canary"))continue;
  last_count=record_append(buffer,last_count,lay,101+n,chunks[index][n]);
 }
 configure(buffer,last_count);
 if(exempt)sus_path_count=0;
 if(scrub_fault)fail_clear_call=1;
 if(swap_fd&&index==0)fd_file=&second_file;
 if(mutate_regs){struct pt_regs *w=(struct pt_regs *)(void*)r;for(unsigned i=0;i<6;i++)w->regs[i]=0xbad+i;}
 return (long)last_count;
}
'''

CASES = r'''
static void reset_case(int id)
{
 expect(!first_file.refs&&!second_file.refs,"previous case leaked no directory reference");
 layout_id=id;fd_file=&first_file;first_dentry.contents=second_dentry.contents=false;
 memset(chunks,0,sizeof(chunks));chunk_count=stream_calls=acquires=releases=reschedules=alternate_gets=0;
 hidden_batches=0;terminal_error=0;pending_signal=scrub_fault=swap_fd=mutate_regs=exempt=false;
 memset(storage,0xa5,8192);last_count=0;memset(&input,0,sizeof(input));
 input.regs[0]=11;input.regs[1]=(unsigned long)buffer;input.regs[2]=4096;
 input.regs[3]=13;input.regs[4]=14;input.regs[5]=15;
}
static long run_case(const char *label,bool verify,long wanted,const char *name)
{
 const struct sus_dirent_layout *lay=layout_id==SUS_DIRENT_COMPAT?&sus_dirent_compat:&sus_dirent_l64;
 long nr=layout_id==SUS_DIRENT_COMPAT?SUS_NR_GETDENTS_COMPAT:__NR_getdents64;
 long result=kstat_dirent_fallback(&input,prior_syscall,nr,layout_id==SUS_DIRENT_COMPAT);
 unsigned records=0,empty=0;const char *first="-";
 if(result>0)for(size_t at=0;at<(size_t)result;){
  unsigned size=record_length(buffer+at,lay);expect(size&&at+size<=(size_t)result,"valid returned record");
  const char *s=(const char*)buffer+at+lay->name_off;
  if(!records)first=s;
  if(!*s)empty++;
  expect(strcmp(s,"ab")||exempt,"hidden ab never returned unless exempt");
  expect(strcmp(s,"skp-private-canary"),"saved syscall's prior filtering preserved");
  if(*s)expect(record_inode(buffer+at,lay)!=0,"visible record retains inode");
  records++;at+=size;
 }
 expect(acquires==releases&&!first_file.refs&&!second_file.refs,"all per-batch references released");
 verify_guards(storage,8192,last_count);
 if(result>=0)expect(!contains(buffer,last_count,"skp-private-canary"),"prior private name absent from buffer");
 printf("case=%s abi=%s result=%ld records=%u empty_names=%u first=\"%s\" original_calls=%u\n",label,
        layout_id==SUS_DIRENT_COMPAT?"compat":"native",result,records,empty,first,stream_calls);
 if(verify){
  expect(!empty,"no empty-name/self entry reaches caller");
  if(wanted<=0)expect(result==wanted,"EOF or original error retained");
  else expect(result>0&&records==(unsigned)wanted,"expected visible record count");
  if(name)expect(!strcmp(first,name),"expected visible name retained");
 }
 return result;
}
int main(int argc,char **argv)
{
 (void)signal_pending;(void)cond_resched;
 bool verify=argc>1&&!strcmp(argv[1],"--verify");
 storage=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
 expect(storage!=MAP_FAILED&&(uintptr_t)storage+8192<UINT32_MAX,"low-address user buffer for real compat cast");
 buffer=storage+16;
 for(int id=0;id<SUS_DIRENT_N;id++){
  reset_case(id);chunk_count=1;chunks[0][0]="ab";chunks[0][1]="123456";
  run_case("before-delete",verify,1,"123456");
  reset_case(id);chunk_count=1;chunks[0][0]="ab";
  run_case("after-delete",verify,0,NULL);
  if(verify)expect(stream_calls==2,"empty filtered batch followed by true EOF");
  reset_case(id);chunk_count=2;chunks[0][0]="ab";chunks[1][0]="later-visible";
  run_case("later-visible-batch",verify,1,"later-visible");
  reset_case(id);chunk_count=1;chunks[0][0]=".";chunks[0][1]="..";chunks[0][2]="ab";
  run_case("dot-records",verify,2,".");
  if(!verify)continue;
  reset_case(id);hidden_batches=513;
  run_case("many-hidden-batches",true,0,NULL);
  expect(stream_calls==514&&reschedules==513,"all hidden batches traversed with scheduling points");
  reset_case(id);chunk_count=1;chunks[0][0]="ab";terminal_error=-EIO;
  run_case("error-after-hidden",true,-EIO,NULL);
  reset_case(id);chunk_count=1;chunks[0][0]="ab";pending_signal=true;
  run_case("signal-after-hidden",true,-EINTR,NULL);expect(stream_calls==1&&!reschedules,"pending signal prevents retry");
  reset_case(id);chunk_count=1;chunks[0][0]="ab";scrub_fault=true;
  run_case("scrub-fault",true,-EFAULT,NULL);expect(stream_calls==1,"scrub error does not retry");
  reset_case(id);chunk_count=2;chunks[0][0]="ab";chunks[1][0]="later-visible";mutate_regs=true;swap_fd=true;
  run_case("fd-reuse-and-register-mutation",true,1,"later-visible");
  expect(alternate_gets==1,"second batch reacquires replacement directory");
  reset_case(id);chunk_count=1;chunks[0][0]="ab";exempt=true;
  run_case("no-active-rule",true,1,"ab");
  reset_case(id);chunk_count=1;chunks[0][0]="ab";first_dentry.contents=true;
  run_case("contents-only",true,0,NULL);
 }
 expect(!munmap(storage,8192),"host buffer released");
 printf("DIRENT_EMPTY_REGRESSION checks=%u verified=%s kernel_calls=false extracted_production=true\n",checks,verify?"true":"false");
 return 0;
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--verify', action='store_true')
    args = p.parse_args()
    root, evidence = args.source_root.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    path = (root / 'kernel/sus_path.c').read_text(encoding='utf-8')
    kstat = (root / 'kernel/susfs_kstat.c').read_text(encoding='utf-8')
    pieces = [extract(path, n, structure=True) for n in ['linux_dirent64', 'sus_dirent64_compat', 'sus_dirent_layout']]
    pieces.append(re.search(r'^enum \{\s*SUS_DIRENT_L64.*?^\};', path, re.M | re.S).group())
    for name in ['sus_dirent_l64', 'sus_dirent_compat']:
        pieces.append(re.search(rf'^static const struct sus_dirent_layout {name} = \{{.*?^\}};', path, re.M | re.S).group())
    pieces.append(COMPACTION_DOUBLES.replace('return hide_all||', 'return !strcmp(name,"ab")||hide_all||'))
    pieces += [filter_function(path, n) for n in ['sus_path_filter', 'sus_path_dirent_filter', 'sus_path_dirent_layout_id']]
    pieces.append(COMPACTION_TESTS[:COMPACTION_TESTS.index('static void test_compaction(void)')])
    pieces.append(SUPPORT)
    post = definition(kstat, 'susfs_kstat_post')
    post = post[:post.index('/* ---- stat family:')] + '}\n'
    post = post.replace('\tstruct kstat_call_counters *c;\n', '').replace('\tstruct kstat_call_state st;\n', '')
    pieces.extend([post, definition(kstat, 'kstat_dirent_fallback'), CASES])
    generated = evidence / 'dirent-empty-extracted.c'
    generated.write_text(COMPACTION_PREAMBLE + '\n'.join(pieces), encoding='utf-8')
    receipt = {'source_root': str(root), 'source_sha256': {n: hashlib.sha256((root/'kernel'/n).read_bytes()).hexdigest() for n in ['sus_path.c','susfs_kstat.c']},
               'extraction': 'Exact filter and syscall wrapper; listing-only prefix of post-check, excluding unused stat locals.',
               'kernel_calls': False, 'runs': []}
    for label, flags in [('strict',['-O2']),('asan-ubsan',['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        binary = evidence / ('dirent-empty-' + label + '.bin')
        command = ['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-Wno-type-limits','-Wno-sign-compare',*flags,execution_path(generated),'-o',execution_path(binary)]
        build = execute(command)
        record = {'name': label, 'build_command': command, 'build_exit': build.returncode, 'build_stdout':build.stdout,'build_stderr':build.stderr}
        if not build.returncode:
            cmd = ['env','ASAN_OPTIONS=detect_leaks=1:abort_on_error=1','UBSAN_OPTIONS=halt_on_error=1',execution_path(binary)] + (['--verify'] if args.verify else [])
            run = execute(cmd)
            record.update(run_command=cmd,run_exit=run.returncode,stdout=run.stdout,stderr=run.stderr)
            (evidence/(label+'.stdout.txt')).write_text(run.stdout,encoding='utf-8')
            (evidence/(label+'.stderr.txt')).write_text(run.stderr,encoding='utf-8')
        receipt['runs'].append(record)
    receipt['passed'] = all(r.get('run_exit') == 0 and not r.get('stderr') for r in receipt['runs'])
    (evidence/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':receipt['passed'],'receipt':str(evidence/'receipt.json')}))
    if not receipt['passed']:
        print(json.dumps(receipt['runs'],indent=2))
    return 0 if receipt['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
