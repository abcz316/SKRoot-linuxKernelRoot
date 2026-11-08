#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check getdents chaining with extracted production wrappers and typed doubles.

The prior syscall double omits a synthetic private canary by name. The SUSFS
postfilter double removes a separate fixture; the forbidden prefilter emits
both. This validates dispatch/ownership, not real SKP or device hiding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from content_entry_regression import definition
from kstat_hook_regression import execute
from path_hook_regression import execution_path, extract


PREAMBLE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define __nocfi
#define noinline __attribute__((noinline))
#define READ_ONCE(x) (x)
#define __NR_getdents64 61
#define SUS_NR_GETDENTS64_COMPAT 217
#define SUS_NR_GETDENTS_COMPAT 141
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct pt_regs { unsigned long regs[8]; };
typedef long (*susfs_syscall_fn_t)(const struct pt_regs *);
struct super_block { unsigned int identity; };
struct inode { struct super_block *i_sb; };
struct dentry { unsigned int unused; };
struct path { struct dentry *dentry; };
struct file { struct inode *inode;unsigned int refs;struct path f_path; };
struct record { char name[32]; };
struct susfs_dirent_call { bool active,covered; };
struct test_task { unsigned int identity; };
static struct test_task fixture_task={1};
#define current (&fixture_task)
static struct super_block directory_sb={71},replacement_sb={99};
static struct inode directory_inode={&directory_sb},replacement_inode={&replacement_sb};
static struct file directory={.inode=&directory_inode},replacement={.inode=&replacement_inode};
static struct file *fd_slot=&directory;
static struct record raw_entries[]={{"visible-fixture"},{"skp-private-canary"},{"susfs-hidden-fixture"}};
static unsigned int checks,orig_calls,post_calls,prefilter_calls,get_calls,put_calls,args_calls;
static unsigned int begin_calls,end_calls;
static unsigned long expected_args[6];
static long expected_nr,original_result;
static bool expected_compat,susfs_hide,missing_fd,swap_fd,change_regs,composed_route;
static char sequence[32];
static void expect(bool condition,const char *message)
{
 ++checks;
 if(!condition){fprintf(stderr,"FAIL check=%u %s sequence=%s\n",checks,message,sequence);exit(1);}
}
static void event(char action)
{ size_t n=strlen(sequence);expect(n+1<sizeof(sequence),"event buffer fits");sequence[n]=action;sequence[n+1]=0; }
static bool has_name(const struct record *entries,size_t bytes,const char *name)
{
 expect(bytes%sizeof(*entries)==0,"fixture record count is aligned");
 for(size_t i=0;i<bytes/sizeof(*entries);i++)if(!strcmp(entries[i].name,name))return true;
 return false;
}
static void syscall_get_arguments(struct test_task *task,struct pt_regs *regs,unsigned long *args)
{
 expect(task==current&&!orig_calls,"arguments are copied before prior syscall");
 memcpy(args,regs->regs,sizeof(expected_args));args_calls++;event('A');
}
static struct file *susfs_dirent_file_get(unsigned int fd)
{
 expect(!orig_calls&&fd==(unsigned int)expected_args[0],"directory FD acquired before prior syscall using saved arg");
 get_calls++;event('G');
 if(missing_fd)return NULL;
 fd_slot->refs++;return fd_slot;
}
static struct inode *file_inode(struct file *file)
{ expect(file&&file->refs==1,"superblock read from held directory reference");return file->inode; }
static void fput(struct file *file)
{
 expect(orig_calls==1&&end_calls==1&&post_calls==(composed_route?0U:1U)&&file==&directory&&file->refs==1,"directory reference released after syscall and composition/fallback completion");
 file->refs--;put_calls++;event('F');
}
static bool susfs_dirent_begin(struct susfs_dirent_call *call,struct file *file,bool compat)
{
 expect(get_calls==1&&!orig_calls&&!begin_calls,"composition begins before prior syscall");
 expect(compat==expected_compat,"composition sees actual ABI");
 expect(missing_fd?file==NULL:(file==&directory&&directory.refs==1),"composition sees held original directory");
 begin_calls++;call->active=composed_route;call->covered=composed_route;event('B');return call->active;
}
static bool susfs_dirent_end(struct susfs_dirent_call *call)
{
 expect(orig_calls==1&&begin_calls==1&&!end_calls&&!post_calls,"composition ends once before fallback");
 expect(missing_fd||directory.refs==1,"directory ref spans composition end");
 end_calls++;call->active=false;event('E');return call->covered;
}
static long prior_skp_syscall(const struct pt_regs *regs)
{
 expect(args_calls==1&&get_calls==1&&begin_calls==1&&!orig_calls&&!post_calls,"prior hook runs once after args, directory acquisition and composition begin");
 expect(missing_fd?directory.refs==0:directory.refs==1,"held directory spans the prior hook");
 orig_calls++;event('O');
 if(swap_fd)fd_slot=&replacement;
 long result=original_result;
 if(result>0){
  struct record *output=(struct record *)regs->regs[1];size_t count=0;
  for(size_t i=0;i<ARRAY_SIZE(raw_entries);i++)
   if(strcmp(raw_entries[i].name,"skp-private-canary")&&
      !(composed_route&&susfs_hide&&!strcmp(raw_entries[i].name,"susfs-hidden-fixture")))output[count++]=raw_entries[i];
  result=(long)(count*sizeof(*output));
 }
 if(change_regs){
  struct pt_regs *mutable=(struct pt_regs *)(void *)regs;
  for(unsigned int i=0;i<6;i++)mutable->regs[i]=0xbad000U+i;
 }
 return result;
}
/* Deliberately dangerous alternate path: a regression that invokes this
 * returns unfiltered private names before the prior SKP hook can run. */
static __attribute__((unused)) bool susfs_dirent_prefilter(const struct pt_regs *regs,long *out,bool compat)
{
 (void)compat;prefilter_calls++;event('P');
 memcpy((void *)regs->regs[1],raw_entries,sizeof(raw_entries));*out=sizeof(raw_entries);return true;
}
static void susfs_kstat_post(long nr,bool compat,const unsigned long *args,long ret,long *out,const struct super_block *sb,const struct dentry *dentry)
{
 (void)dentry;
 expect(orig_calls==1&&end_calls==1&&!post_calls,"SUSFS postfilter runs once after prior hook and composition fallback");
 expect(nr==expected_nr&&compat==expected_compat,"native and compat syscall identity is preserved");
 expect(!memcmp(args,expected_args,sizeof(expected_args)),"all six original arguments survive prior hook mutation");
 expect(missing_fd?sb==NULL:(sb==&directory_sb&&directory.refs==1),"postfilter uses original held filesystem even after FD reuse");
 post_calls++;event('S');
 if(ret<=0){expect(*out==ret,"original error or EOF propagated into postfilter");return;}
 struct record *entries=(struct record *)args[1];
 expect(!has_name(entries,(size_t)ret,"skp-private-canary"),"prior SKP canary filtering is preserved");
 if(susfs_hide){
  size_t count=0;
  for(size_t i=0;i<(size_t)ret/sizeof(*entries);i++)
   if(strcmp(entries[i].name,"susfs-hidden-fixture"))entries[count++]=entries[i];
  *out=(long)(count*sizeof(*entries));
 }
}
static bool signal_pending(struct test_task *task)
{ expect(task==current,"signal check uses current task");return false; }
static void cond_resched(void)
{ expect(false,"single-batch chain scenarios never need an internal retry"); }
static susfs_syscall_fn_t kstat_orig_getdents64=prior_skp_syscall;
static susfs_syscall_fn_t kstat_orig_compat_getdents64=prior_skp_syscall;
static susfs_syscall_fn_t kstat_orig_compat_getdents=prior_skp_syscall;
'''

TESTS = r'''
static void reset(struct pt_regs *regs,struct record *buffer,size_t bytes,long nr,bool compat)
{
 expect(!directory.refs&&!replacement.refs,"previous case leaked no file references");
 orig_calls=post_calls=prefilter_calls=get_calls=put_calls=args_calls=begin_calls=end_calls=0;sequence[0]=0;
 expected_nr=nr;expected_compat=compat;original_result=sizeof(raw_entries);
 susfs_hide=missing_fd=swap_fd=change_regs=composed_route=false;fd_slot=&directory;
 memset(buffer,0,bytes);memset(regs,0,sizeof(*regs));
 expected_args[0]=11;expected_args[1]=(unsigned long)buffer;expected_args[2]=bytes;
 expected_args[3]=0x12345678;expected_args[4]=0xaabbccdd;expected_args[5]=0x31415926;
 memcpy(regs->regs,expected_args,sizeof(expected_args));
 kstat_orig_getdents64=kstat_orig_compat_getdents64=kstat_orig_compat_getdents=prior_skp_syscall;
}
static void verify_finished(bool no_file)
{
 expect(orig_calls==1&&post_calls==(composed_route?0U:1U)&&begin_calls==1&&end_calls==1&&!prefilter_calls,"original hook and qualified completion/fallback run once; alternate prefilter never runs");
 expect(get_calls==1&&put_calls==(no_file?0U:1U)&&!directory.refs&&!replacement.refs,"FD ownership balances on completion");
 expect(!strcmp(sequence,composed_route?"AGBOEF":no_file?"AGBOES":"AGBOESF"),"arguments, directory acquisition, composition, original, end, fallback and release order");
}
int main(void)
{
 const struct {long nr;bool compat;susfs_syscall_fn_t wrapper;susfs_syscall_fn_t *slot;} routes[]={
  {__NR_getdents64,false,kstat_wrap_getdents64,&kstat_orig_getdents64},
  {SUS_NR_GETDENTS64_COMPAT,true,kstat_wrap_compat_getdents64,&kstat_orig_compat_getdents64},
  {SUS_NR_GETDENTS_COMPAT,true,kstat_wrap_compat_getdents,&kstat_orig_compat_getdents}
 };
 for(size_t route=0;route<ARRAY_SIZE(routes);route++){
  struct pt_regs regs;struct record entries[ARRAY_SIZE(raw_entries)];long result;
  reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);
  result=routes[route].wrapper(&regs);
  expect(!prefilter_calls&&orig_calls==1,"empty SUSFS rules still chain prior SKP protection");
  expect(result==2*(long)sizeof(*entries)&&!has_name(entries,(size_t)result,"skp-private-canary"),"prior private directory remains absent");
  expect(has_name(entries,(size_t)result,"susfs-hidden-fixture"),"empty SUSFS rules leave unrelated entry alone");
  verify_finished(false);

  reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);susfs_hide=true;
  result=routes[route].wrapper(&regs);
  expect(result==(long)sizeof(*entries)&&!strcmp(entries[0].name,"visible-fixture"),"SUSFS postfilter composes with prior private filtering");
  verify_finished(false);

  if(!routes[route].compat){
   reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);susfs_hide=composed_route=true;
   result=routes[route].wrapper(&regs);
   expect(result==(long)sizeof(*entries)&&!strcmp(entries[0].name,"visible-fixture"),"fully composed native chain preserves original answer without second postfilter");
   verify_finished(false);
  }

  reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);swap_fd=change_regs=true;
  result=routes[route].wrapper(&regs);
  expect(result==2*(long)sizeof(*entries)&&fd_slot==&replacement,"reference and saved args survive in-flight descriptor replacement");
  verify_finished(false);

  for(unsigned int i=0;i<2;i++){
   reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);original_result=i?-EIO:0;
   result=routes[route].wrapper(&regs);expect(result==original_result,"prior EOF or error stays unchanged");
   verify_finished(false);
  }
  reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);missing_fd=true;original_result=-EBADF;
  expect(routes[route].wrapper(&regs)==-EBADF,"missing held fd retains original syscall error");verify_finished(true);

  reset(&regs,entries,sizeof(entries),routes[route].nr,routes[route].compat);*routes[route].slot=NULL;
  expect(routes[route].wrapper(&regs)==-ENOSYS,"absent prior syscall slot refuses call");
  expect(!args_calls&&!get_calls&&!orig_calls&&!post_calls&&!put_calls&&!prefilter_calls&&!begin_calls&&!end_calls,"NULL slot touches no arguments, file, composition or alternate path");
 }
 printf("DIRENT_CHAIN_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",checks);return 0;
}
'''


COMPACTION_PREAMBLE = r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef int64_t s64;
#define __user
#define READ_ONCE(x) (x)
#define NAME_MAX 255
#define DIRENT_BUF_SIZE 65536
#define ALIGN(value, alignment) (((value)+(alignment)-1)&~((alignment)-1))
#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8
#define __NR_getdents64 61
#define SUS_NR_GETDENTS64_COMPAT 217
#define SUS_NR_GETDENTS_COMPAT 141
#define pr_warn_ratelimited(...) ((void)0)
struct super_block { unsigned int identity; };
typedef struct { unsigned int value; } atomic_t;
static void atomic_inc(atomic_t *counter) { counter->value++; }
static unsigned int checks;
static void expect(bool condition,const char *message)
{
 ++checks;if(!condition){fprintf(stderr,"FAIL check=%u %s\n",checks,message);exit(1);}
}
'''

COMPACTION_DOUBLES = r'''
static atomic_t n_dirent_calls[SUS_DIRENT_N],n_dirent_syscall_bad[SUS_DIRENT_N];
static atomic_t n_dirent_buf_null[SUS_DIRENT_N],n_dirent_no_rule[SUS_DIRENT_N],n_dirent_no_filter[SUS_DIRENT_N];
static atomic_t n_dirent_rewrite_fail,n_dirent_all_hidden;
static bool no_extra,sus_path_buf_lock,faults_disabled,hide_all,has_group_rules,named_mode;
static unsigned int sus_path_count,reads,writes,clears,matches;
static unsigned int fail_write_call,fail_clear_call;
static size_t clear_fault_prefix;
static char hide_name[32],scratch[DIRENT_BUF_SIZE];
static char *dirent_tmp=scratch;
static unsigned char *user_begin;
static size_t user_count;
static struct super_block original_sb={71};
static bool skp_policy_paths_present(void) { return has_group_rules; }
static bool skp_policy_directory_names_present(void) { return named_mode; }
static bool susfs_directory_entry_hidden(const char *name,int length,unsigned int type)
{ return named_mode&&(type==DT_DIR||type==DT_REG)&&length==5&&!memcmp(name,"named",5); }
static void spin_lock(bool *lock)
{ expect(!*lock,"scratch lock is acquired once");*lock=true; }
static void spin_unlock(bool *lock)
{ expect(*lock&&!faults_disabled,"faults restored before scratch unlock");*lock=false; }
static void pagefault_disable(void)
{ expect(sus_path_buf_lock&&!faults_disabled,"scratch critical section disables faults");faults_disabled=true; }
static void pagefault_enable(void)
{ expect(sus_path_buf_lock&&faults_disabled,"scratch critical section reenables faults");faults_disabled=false; }
static void check_user_range(const void *pointer,size_t bytes)
{
 uintptr_t p=(uintptr_t)pointer,b=(uintptr_t)user_begin;
 expect(p>=b&&p-b<=user_count&&bytes<=user_count-(p-b),"uaccess stays within original returned byte count");
}
static unsigned long copy_from_user(void *to,const void *from,size_t bytes)
{ check_user_range(from,bytes);expect(sus_path_buf_lock&&faults_disabled,"input reads occur in scratch critical section");reads++;memcpy(to,from,bytes);return 0; }
static unsigned long copy_to_user(void *to,const void *from,size_t bytes)
{
 check_user_range(to,bytes);writes++;
 if(fail_write_call==writes)return bytes;
 memcpy(to,from,bytes);return 0;
}
static unsigned long clear_user(void *to,size_t bytes)
{
 check_user_range(to,bytes);expect(!sus_path_buf_lock&&!faults_disabled,"tail scrubbing occurs outside scratch lock");clears++;
 if(fail_clear_call==clears){
  size_t changed=clear_fault_prefix<bytes?clear_fault_prefix:bytes;
  memset(to,0,changed);return bytes-changed;
 }
 memset(to,0,bytes);return 0;
}
static long strnlen_user(const char *name,size_t limit)
{
 expect(sus_path_buf_lock&&faults_disabled,"name read occurs in scratch critical section");
 for(size_t i=0;i<limit;i++){check_user_range(name+i,1);reads++;if(!name[i])return (long)i+1;}
 return (long)limit+1;
}
static bool sus_path_is_hidden(const struct super_block *sb,u64 ino,const char *name)
{
 matches++;expect(sb==&original_sb&&ino!=0,"compaction matches original directory filesystem and inode");
 expect(strcmp(name,"skp-private-canary"),"private canary absent from prior hook output never enters SUSFS matcher");
 return hide_all||!strncmp(name,"susfs-hidden",12);
}
'''

COMPACTION_TESTS = r'''
static size_t record_append(unsigned char *buffer,size_t offset,const struct sus_dirent_layout *layout,u64 ino,const char *name)
{
 size_t align=layout->ino_size,bytes=(layout->name_off+strlen(name)+1+
     (layout->id==SUS_DIRENT_COMPAT?1:0)+align-1)&~(align-1);
 unsigned short reclen=(unsigned short)bytes;
 memset(buffer+offset,0,bytes);memcpy(buffer+offset,&ino,layout->ino_size);
 memcpy(buffer+offset+layout->reclen_off,&reclen,sizeof(reclen));
 memcpy(buffer+offset+layout->name_off,name,strlen(name)+1);return offset+bytes;
}
static unsigned short record_length(const unsigned char *record,const struct sus_dirent_layout *layout)
{ unsigned short length;memcpy(&length,record+layout->reclen_off,sizeof(length));return length; }
static u64 record_inode(const unsigned char *record,const struct sus_dirent_layout *layout)
{ u64 ino=0;memcpy(&ino,record,layout->ino_size);return ino; }
static bool contains(const unsigned char *buffer,size_t bytes,const char *needle)
{ size_t n=strlen(needle);for(size_t i=0;i+n<=bytes;i++)if(!memcmp(buffer+i,needle,n))return true;return false; }
static void configure(unsigned char *begin,size_t count)
{
 expect(!sus_path_buf_lock&&!faults_disabled,"previous compaction released scratch state");
 user_begin=begin;user_count=count;reads=writes=clears=matches=0;
 fail_write_call=fail_clear_call=0;clear_fault_prefix=0;
 no_extra=hide_all=has_group_rules=named_mode=false;sus_path_count=1;hide_name[0]=0;dirent_tmp=scratch;
}
static void verify_guards(const unsigned char *storage,size_t total,size_t count)
{
 for(size_t i=0;i<16;i++)expect(storage[i]==0xa5,"leading buffer guard unchanged");
 for(size_t i=16+count;i<total;i++)expect(storage[i]==0xa5,"bytes after original return remain untouched");
}
static void test_compaction(void)
{
 for(int id=0;id<SUS_DIRENT_N;id++){
  const struct sus_dirent_layout *layout=id==SUS_DIRENT_COMPAT?&sus_dirent_compat:&sus_dirent_l64;
  unsigned char storage[512],before[512];unsigned char *buffer=storage+16;
  memset(storage,0xa5,sizeof(storage));size_t count=0;
  count=record_append(buffer,count,layout,101,"visible-one");
  size_t first= count;
  count=record_append(buffer,count,layout,202,"susfs-hidden-fixture");
  count=record_append(buffer,count,layout,303,"visible-two");
  configure(buffer,count);long result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false);
  expect(result>0&&(size_t)result<count&&matches==3,"partial hiding compacts returned records");
  expect(!strcmp((char *)buffer+layout->name_off,"visible-one")&&record_inode(buffer,layout)==101,"first visible entry unchanged");
  expect(!strcmp((char *)buffer+first+layout->name_off,"visible-two")&&record_inode(buffer+first,layout)==303,"later visible entry moves into gap");
  expect(first+record_length(buffer+first,layout)==(size_t)result,"returned count ends on compacted record boundary");
  expect(!contains(buffer,count,"skp-private-canary")&&!contains(buffer,count,"susfs-hidden-fixture"),"neither prior private nor SUSFS-hidden names reappear in returned allocation");
  for(size_t i=(size_t)result;i<count;i++)expect(buffer[i]==0,"dropped record tail cleared");
  expect(clears==1&&!sus_path_buf_lock&&!faults_disabled,"partial tail cleanup completes after unlock");verify_guards(storage,sizeof(storage),count);

  memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,101,"susfs-hidden-one");first=count;
  count=record_append(buffer,count,layout,202,"susfs-hidden-two");configure(buffer,count);
  result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false);
  expect(result==0,"fully hidden batch returns no synthetic records");
  for(size_t i=0;i<count;i++)expect(buffer[i]==0,"all-hidden batch scrubs headers and names");
  expect(clears==1&&!writes&&!sus_path_buf_lock&&!faults_disabled,"all-hidden scrub happens after unlock");verify_guards(storage,sizeof(storage),count);

  memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,1,".");
  size_t dot_bytes=count;count=record_append(buffer,count,layout,2,"..");dot_bytes=count;
  const char *children[]={"file","directory","symlink","fifo","socket","device"};
  for(unsigned i=0;i<sizeof(children)/sizeof(children[0]);i++)count=record_append(buffer,count,layout,100+i,children[i]);
  configure(buffer,count);has_group_rules=true;
  result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,true);
  expect(result==(long)dot_bytes,"contents fallback keeps only dot records");
  expect(!strcmp((char*)buffer+layout->name_off,".")&&!strcmp((char*)buffer+record_length(buffer,layout)+layout->name_off,".."),"contents fallback preserves dot ordering");
  for(unsigned i=0;i<sizeof(children)/sizeof(children[0]);i++)expect(!contains(buffer,count,children[i]),"contents fallback scrubs every hidden child name");
  for(size_t i=dot_bytes;i<count;i++)expect(!buffer[i],"contents fallback scrubs returned buffer tail");
  verify_guards(storage,sizeof(storage),count);

  for(unsigned int bad=0;bad<2;bad++){
   memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,101,"visible-one");configure(buffer,count);memcpy(before,storage,sizeof(storage));
   long ret=bad?-EIO:0;expect(sus_path_dirent_filter(id,(unsigned long)buffer,ret,&original_sb,false)==ret,"error and EOF preserve original result");
   expect(!reads&&!writes&&!clears&&!matches&&!memcmp(storage,before,sizeof(storage)),"error and EOF never touch output buffer");
  }
  memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,101,"visible-one");configure(buffer,count);sus_path_count=0;memcpy(before,storage,sizeof(storage));
  expect(sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false)==(long)count&&!reads&&!writes&&!memcmp(storage,before,sizeof(storage)),"no SUSFS rules preserve previous hook's exact bytes");
  configure(buffer,count);no_extra=true;
  expect(sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false)==(long)count&&!reads&&!writes,"no-extra mode never rewrites prior output");
  configure(buffer,count);unsigned short invalid=(unsigned short)(count+8);memcpy(buffer+layout->reclen_off,&invalid,sizeof(invalid));memcpy(before,storage,sizeof(storage));
  expect(sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false)==(long)count,"record extending past return count is rejected");
  expect(!writes&&!clears&&!memcmp(storage,before,sizeof(storage)),"malformed first record leaves original bytes unchanged");verify_guards(storage,sizeof(storage),count);
  /* Drive the actual production native + old compat d_type extraction. */
  for(unsigned int type=0;type<=12;type++) {
   memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,101,"named");
   first=count;count=record_append(buffer,count,layout,202,"visible");
   size_t type_at=layout->id==SUS_DIRENT_COMPAT?first-1:offsetof(struct linux_dirent64,d_type);
   buffer[type_at]=(unsigned char)type;configure(buffer,count);named_mode=has_group_rules=true;
   result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false);
   bool selected=type==DT_DIR||type==DT_REG;
   expect(!strcmp((char*)buffer+layout->name_off,selected?"visible":"named"),
       "full-name rule filters directory/regular types only, including compat tail type");
   expect(result==(long)(selected?count-first:count),"typed name filtering adjusts returned length");
   verify_guards(storage,sizeof(storage),count);
  }
 }
 expect(sus_path_dirent_layout_id(__NR_getdents64,false)==SUS_DIRENT_L64,"native number selects 64-bit layout");
 expect(sus_path_dirent_layout_id(SUS_NR_GETDENTS64_COMPAT,true)==SUS_DIRENT_L64,"compat getdents64 retains native record layout");
 expect(sus_path_dirent_layout_id(SUS_NR_GETDENTS_COMPAT,true)==SUS_DIRENT_COMPAT,"compat getdents selects 32-bit record layout");
}
static void test_empty_batches(void)
{
 const char *names[]={"a","alpha","confidential-folder-0123456789","longer-hidden-file-name-which-crosses-eight-byte-alignment"};
 for(int id=0;id<SUS_DIRENT_N;id++){
  const struct sus_dirent_layout *layout=id==SUS_DIRENT_COMPAT?&sus_dirent_compat:&sus_dirent_l64;
  for(unsigned int mode=0;mode<2;mode++)for(unsigned int sample=0;sample<sizeof(names)/sizeof(names[0]);sample++)for(unsigned int kind=0;kind<2;kind++){
   unsigned char storage[512];unsigned char *buffer=storage+16;
   memset(storage,0xa5,sizeof(storage));size_t first=record_append(buffer,0,layout,101,names[sample]);
   size_t count=record_append(buffer,first,layout,202,"second-hidden-child");
   size_t type_at=id==SUS_DIRENT_COMPAT?first-1:offsetof(struct linux_dirent64,d_type);
   buffer[type_at]=kind?DT_REG:DT_DIR;
   configure(buffer,count);hide_all=!mode;has_group_rules=mode;
   long result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,mode);
   expect(result==0,"fully hidden batch has no empty-name/self entry in either mode");
   for(size_t i=0;i<count;i++)expect(buffer[i]==0,"empty batch scrubs all original records including headers");
   expect(clears==1&&!writes&&!sus_path_buf_lock&&!faults_disabled,"empty batch clears outside scratch lock");
   verify_guards(storage,sizeof(storage),count);
   memset(storage,0xa5,sizeof(storage));count=record_append(buffer,0,layout,303,"visible-next-chunk");
   configure(buffer,count);
   result=sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,false);
   expect(result==(long)count&&!strcmp((char*)buffer+layout->name_off,"visible-next-chunk"),"subsequent visible batch remains filterable");
   verify_guards(storage,sizeof(storage),count);
  }
  for(unsigned int mode=0;mode<2;mode++)for(unsigned int partial=0;partial<2;partial++){
   unsigned char storage[512];unsigned char *buffer=storage+16;
   memset(storage,0xa5,sizeof(storage));size_t first=record_append(buffer,0,layout,101,"first-child");
   size_t count=record_append(buffer,first,layout,202,"second-child");
   configure(buffer,count);hide_all=!mode;has_group_rules=mode;fail_clear_call=1;clear_fault_prefix=partial?first:0;
   unsigned int failures=n_dirent_rewrite_fail.value,success=n_dirent_all_hidden.value;
   expect(sus_path_dirent_filter(id,(unsigned long)buffer,(long)count,&original_sb,mode)==-EFAULT,"empty batch scrub fault returns EFAULT");
   expect(clears==1&&!writes&&n_dirent_rewrite_fail.value==failures+1&&n_dirent_all_hidden.value==success,"failed scrub is counted without claiming empty success");
   expect(!sus_path_buf_lock&&!faults_disabled,"failed scrub releases scratch resources");
   verify_guards(storage,sizeof(storage),count);
  }
 }
}
int main(void)
{
 test_compaction();test_empty_batches();printf("DIRENT_COMPACTION_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",checks);return 0;
}
'''


def filter_function(source: str, name: str) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = rf"^(?:static\s+)?(?:long|int)\s+{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production filter {name}")
    start, depth = matches[0].start(), 0
    for cursor in range(masked.index("{", start), len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            return source[start:cursor + 1]
    raise ValueError(f"unbalanced production filter {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--mutation", choices=["none", "prefilter-bypass"], default="none")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    source_path = repo / "kernel/susfs_kstat.c"
    source = source_path.read_text(encoding="utf-8")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    names = ["kstat_dirent_fallback", "kstat_wrap_getdents64", "kstat_wrap_compat_getdents64", "kstat_wrap_compat_getdents"]
    pieces = {name: definition(source, name) for name in names}
    if args.mutation == "prefilter-bypass":
        for name in names[1:]:
            flag = "true" if name == "kstat_wrap_compat_getdents" else "false"
            needle = "\treturn kstat_dirent_fallback("
            if needle not in pieces[name]:
                raise ValueError("production wrapper no longer has expected fallback call")
            pieces[name] = pieces[name].replace(needle, "\tlong raw_result;\n\tif (susfs_dirent_prefilter(regs, &raw_result, " + flag + "))\n\t\treturn raw_result;\n" + needle, 1)
    generated = evidence / "dirent-chain-extracted.c"
    generated.write_text(PREAMBLE + "\n" + "\n\n".join(pieces.values()) + TESTS, encoding="utf-8")
    path_source_file = repo / "kernel/sus_path.c"
    path_source = path_source_file.read_text(encoding="utf-8")
    filter_pieces = {name: extract(path_source, name, structure=True)
                     for name in ["linux_dirent64", "sus_dirent64_compat", "sus_dirent_layout"]}
    enum = re.search(r"^enum \{\s*SUS_DIRENT_L64.*?^\};", path_source, re.M | re.S)
    if not enum:
        raise ValueError("production dirent layout enum missing")
    filter_pieces["layout_enum"] = enum.group()
    for name in ["sus_dirent_l64", "sus_dirent_compat"]:
        initializer = re.search(rf"^static const struct sus_dirent_layout {name} = \{{.*?^\}};", path_source, re.M | re.S)
        if not initializer:
            raise ValueError(f"production layout initializer {name} missing")
        filter_pieces[name] = initializer.group()
    filter_functions = {name: filter_function(path_source, name)
                        for name in ["sus_path_filter", "sus_path_dirent_filter", "sus_path_dirent_layout_id"]}
    compacted = evidence / "dirent-compaction-extracted.c"
    compacted.write_text(COMPACTION_PREAMBLE + "\n" + "\n".join(filter_pieces.values()) +
                         COMPACTION_DOUBLES + "\n" + "\n".join(filter_functions.values()) + COMPACTION_TESTS,
                         encoding="utf-8")
    receipt = {"production_source": "kernel/susfs_kstat.c", "mutation": args.mutation, "kernel_calls": False,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "additional_source_sha256": {"kernel/sus_path.c": hashlib.sha256(path_source_file.read_bytes()).hexdigest()},
               "extracted_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in pieces.items()},
               "compaction_extracted_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in {**filter_pieces, **filter_functions}.items()},
               "limits": "Synthetic prior SKP hook and typed uaccess/matcher doubles with actual compaction; not actual private-directory or device verification.", "runs": []}
    runs = [(kind, code, marker, label, flags)
            for kind, code, marker in [("chain", generated, "DIRENT_CHAIN_REGRESSION"),
                                       ("compaction", compacted, "DIRENT_COMPACTION_REGRESSION")]
            for label, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]]
    for kind, code, marker, label, flags in runs:
        name = kind + "-" + label
        binary = evidence / ("dirent-" + name + ".bin")
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                   execution_path(code), "-o", execution_path(binary)]
        if kind == "compaction":
            # Preserve the production u16/65536 and signed strnlen comparisons.
            command += ["-Wno-type-limits", "-Wno-sign-compare"]
        build = execute(command)
        (evidence / (name + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": name, "build_exit": build.returncode, "passed": False}
        if build.returncode == 0:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (name + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (name + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(marker + r" checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "dirent-chain-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
