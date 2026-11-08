#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run actual production directory-composition functions against typed doubles.

The request, guard, actor, probe handlers, restoration and stop functions are
extracted verbatim from kernel/sus_dirent.c; path name validation is extracted
from sus_path.c. Kernel probes/CFI/VFS and device effects are not simulated proof.
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
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef long long test_loff_t;
#define loff_t test_loff_t
#define __nocfi
#define noinline __attribute__((noinline))
#define static_assert _Static_assert
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#ifndef TEST_KERNEL_VERSION
#define TEST_KERNEL_VERSION KERNEL_VERSION(6,12,0)
#endif
#define LINUX_VERSION_CODE TEST_KERNEL_VERSION
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_RELAXED)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),(v),__ATOMIC_RELAXED)
#define EXT4_SUPER_MAGIC 0xef53
#define F2FS_SUPER_MAGIC 0xf2f52010
#define FUSE_SUPER_MAGIC 0x65735546
#define NAME_MAX 255
#define THIS_MODULE NULL
#define unlikely(x) (x)
struct dir_context;
typedef bool (*filldir_t)(struct dir_context *,const char *,int,loff_t,u64,unsigned int);
struct dir_context { filldir_t actor;loff_t pos;unsigned long cookie;void *private_data;char *output;size_t used,capacity;bool block; };
struct super_block { unsigned long s_magic;u64 s_dev; };
struct inode { struct super_block *i_sb; };
struct file_operations { unsigned int identity; };
struct dentry { unsigned int unused; };
struct path { struct dentry *dentry; };
struct file { struct path f_path; struct inode *f_inode;unsigned int refs;const struct file_operations *f_op; };
struct task_struct { unsigned int id,uid;bool manager; };
static struct task_struct app={1,10123,false},manager={3,10123,true},root_task={4,0,false};
static _Thread_local struct task_struct *current;
struct pt_regs { unsigned long regs[31];unsigned long sp; };
struct kprobe { unsigned long nmissed; };
struct kretprobe { int nmissed; };
struct kretprobe_instance { _Alignas(max_align_t) unsigned char data[256]; };
typedef struct { atomic_int value; } atomic_t;
typedef struct { atomic_llong value; } atomic64_t;
#define ATOMIC_INIT(x) {ATOMIC_VAR_INIT(x)}
#define ATOMIC64_INIT(x) {ATOMIC_VAR_INIT(x)}
static void atomic_inc(atomic_t *a) { atomic_fetch_add(&a->value,1); }
static void atomic_dec(atomic_t *a) { assert(atomic_fetch_sub(&a->value,1)>0); }
static int atomic_read(const atomic_t *a) { return atomic_load(&a->value); }
static void atomic64_inc(atomic64_t *a) { atomic_fetch_add(&a->value,1); }
static atomic_uint checks;
static void expect(bool condition,const char *message)
{ unsigned int n=atomic_fetch_add(&checks,1)+1;if(!condition){fprintf(stderr,"FAIL check=%u %s\n",n,message);abort();} }
static _Thread_local unsigned int held_spin;
static pthread_mutex_t sd_lock=PTHREAD_MUTEX_INITIALIZER,sd_stop_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned int sd_wait;
#define raw_spin_lock_irqsave(lock,flags) do {(flags)=0;expect(!pthread_mutex_lock(lock),"take composition lock");held_spin++;}while(0)
#define raw_spin_unlock_irqrestore(lock,flags) do {(void)(flags);expect(held_spin>0,"drop held composition lock");held_spin--;expect(!pthread_mutex_unlock(lock),"unlock composition state");}while(0)
#define mutex_lock(lock) expect(!pthread_mutex_lock(lock),"take lifecycle mutex")
#define mutex_unlock(lock) expect(!pthread_mutex_unlock(lock),"drop lifecycle mutex")
static pthread_mutex_t wait_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_cond=PTHREAD_COND_INITIALIZER;
#define wait_event(queue,condition) do {(void)(queue);expect(!held_spin,"wait outside spinlock");pthread_mutex_lock(&wait_lock);while(!(condition))pthread_cond_wait(&wait_cond,&wait_lock);pthread_mutex_unlock(&wait_lock);}while(0)
static void wake_up_all(unsigned int *queue) { (void)queue;pthread_mutex_lock(&wait_lock);pthread_cond_broadcast(&wait_cond);pthread_mutex_unlock(&wait_lock); }
struct hlist_node { struct hlist_node *next;struct hlist_node **prev; };
struct hlist_head { struct hlist_node *first; };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define bucket(table,key) (((uintptr_t)(key)>>2)&(ARRAY_SIZE(table)-1))
#define HASH_BITS(table) 8U
#define hash_min(key,bits) (((uintptr_t)(key)>>2)&((1U<<(bits))-1U))
#define hlist_for_each(node,head) for((node)=(head)->first;(node);(node)=(node)->next)
#define hash_for_each_possible(table,pos,member,key) for(struct hlist_node *_p=(table)[bucket(table,key)].first;_p&&((pos)=container_of(_p,typeof(*(pos)),member),true);_p=_p->next)
static void add_hash(struct hlist_head *head,struct hlist_node *node)
{node->next=head->first;node->prev=&head->first;if(node->next)node->next->prev=&node->next;head->first=node;}
#define hash_add(table,node,key) add_hash(&(table)[bucket(table,key)],node)
static void hash_del(struct hlist_node *node)
{ expect(node->prev!=NULL,"active request is linked");*node->prev=node->next;if(node->next)node->next->prev=node->prev;node->next=NULL;node->prev=NULL; }
'''

GLOBALS = r'''
static struct hlist_head sd_calls[256];
static const struct file_operations ext4_ops={1},f2fs_ops={2},custom_ops={3};
static const struct file_operations *sd_ext4_dir_ops=&ext4_ops,*sd_f2fs_dir_ops=&f2fs_ops;
static bool sd_ready=true,sd_accepting=true,sd_call_installed,sd_post_installed,sd_return_installed;
static atomic_t sd_active=ATOMIC_INIT(0),sd_bindings=ATOMIC_INIT(0);
static atomic64_t sd_begun=ATOMIC64_INIT(0),sd_covered=ATOMIC64_INIT(0),sd_fallback=ATOMIC64_INIT(0);
static atomic64_t sd_attached=ATOMIC64_INIT(0),sd_restored=ATOMIC64_INIT(0),sd_ret_recovered=ATOMIC64_INIT(0);
static atomic64_t sd_forwarded=ATOMIC64_INIT(0),sd_hidden=ATOMIC64_INIT(0),sd_conflicts=ATOMIC64_INIT(0),sd_entry_misses=ATOMIC64_INIT(0);
static atomic64_t sd_reject_compat=ATOMIC64_INIT(0),sd_reject_not_ready=ATOMIC64_INIT(0),sd_reject_file=ATOMIC64_INIT(0),sd_reject_filesystem=ATOMIC64_INIT(0);
static struct kprobe sd_call_probe,sd_post_probe;
static struct kretprobe sd_return_probe;
static atomic_int module_refs;
static bool module_accepting=true,reject_during_pin,actor_type_valid=true;
static atomic_bool stop_started,stop_finished;
static unsigned int unregister_order[3],unregister_count,rule_calls;
static struct inode *file_inode(struct file *file) {expect(file->refs>0,"caller keeps original file held");return file->f_inode;}
static bool try_module_get(void *module)
{(void)module;expect(!held_spin,"module lifetime pinned before composition lock");if(!module_accepting)return false;atomic_fetch_add(&module_refs,1);if(reject_during_pin)WRITE_ONCE(sd_accepting,false);return true;}
static void module_put(void *module)
{(void)module;expect(!held_spin,"module reference released outside lock");expect(atomic_fetch_sub(&module_refs,1)>0,"module reference balances");}
static bool prior_actor(struct dir_context *,const char *,int,loff_t,u64,unsigned int);
static bool foreign_actor(struct dir_context *,const char *,int,loff_t,u64,unsigned int);
static int copy_from_kernel_nofault(void *out,const void *from,size_t bytes)
{
 expect(bytes==4,"actor type read is one KCFI word");
 if((uintptr_t)from==(uintptr_t)prior_actor-4||(uintptr_t)from==(uintptr_t)foreign_actor-4){u32 cfi=actor_type_valid?SD_ACTOR_CFI:0;memcpy(out,&cfi,4);return 0;}
 return -EFAULT;
}
static bool no_extra,has_rules=true,scope_applies=true;
static bool named_mode, contents_mode;
static bool skp_policy_path_contents_hidden(const struct dentry *directory, bool include_self)
{
 (void)directory;expect(include_self,"directory enumeration includes the anchor");
 return contents_mode && scope_applies && !current->manager && !no_extra;
}
static unsigned int expected_type=8;
static bool susfs_directory_entry_hidden(const char *name,int length,unsigned int type)
{
 return named_mode&&!no_extra&&scope_applies&&!current->manager&&
        (type==4||type==8)&&length==10&&!memcmp(name,"named-only",10);
}
static unsigned int sus_path_count=1;
static char hide_name[32];
static bool skp_policy_paths_present(void) {return has_rules;}
static bool sus_path_is_hidden(const struct super_block *sb,u64 ino,const char *name)
{
 expect(!held_spin,"policy and original actor execute outside registry lock");rule_calls++;
 expect(sb&&sb->s_dev==11&&ino==77,"matcher uses held directory device and actual entry inode");
 return scope_applies&&!current->manager&&!strcmp(name,"susfs-only");
}
static pthread_mutex_t block_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t block_cond=PTHREAD_COND_INITIALIZER;
static bool original_entered,original_released;
static void (*reenter_original)(struct dir_context *);
static bool name_equal(const char *name,int len,const char *want)
{return len>=0&&strlen(want)==(size_t)len&&!memcmp(name,want,(size_t)len);}
static bool prior_actor(struct dir_context *ctx,const char *name,int len,loff_t off,u64 ino,unsigned int type)
{
 expect(!held_spin,"potentially sleeping original is never called under registry lock");
 expect(ctx->cookie==0x12345678UL&&ctx->private_data==ctx,"original context and private tail are preserved");
 expect(off==ctx->pos+1&&ino==77&&type==expected_type,"original callback arguments are unchanged");
 if(!current->manager&&name_equal(name,len,"private-canary"))return true;
 if(name_equal(name,len,"io-error"))return false;
 if(reenter_original){void (*nested)(struct dir_context *)=reenter_original;reenter_original=NULL;nested(ctx);}
 if(ctx->block){pthread_mutex_lock(&block_lock);original_entered=true;pthread_cond_broadcast(&block_cond);while(!original_released)pthread_cond_wait(&block_cond,&block_lock);pthread_mutex_unlock(&block_lock);}
 if((size_t)len+1>ctx->capacity-ctx->used)return false;
 memcpy(ctx->output+ctx->used,name,(size_t)len);ctx->output[ctx->used+(size_t)len]='\n';ctx->used+=(size_t)len+1;return true;
}
static bool foreign_actor(struct dir_context *ctx,const char *name,int len,loff_t off,u64 ino,unsigned int type)
{return prior_actor(ctx,name,len,off,ino,type);}
static void unregister_kprobe(struct kprobe *probe)
{
 expect(!held_spin,"probe removal occurs outside registry lock");
 if(probe==&sd_call_probe){unregister_order[unregister_count++]=1;atomic_store(&stop_started,true);}
 else{expect(probe==&sd_post_probe&&!atomic_read(&sd_active),"restore postsite remains installed until all requests exit");unregister_order[unregister_count++]=2;}
}
static void unregister_kretprobe(struct kretprobe *probe)
{expect(!held_spin&&probe==&sd_return_probe&&!atomic_read(&sd_active),"return recovery removed only after request drain");unregister_order[unregister_count++]=3;}
static bool sd_actor(struct dir_context *,const char *,int,loff_t,u64,unsigned int);
'''

TESTS = r'''
static struct super_block local_sb={EXT4_SUPER_MAGIC,11},other_sb={FUSE_SUPER_MAGIC,11};
static struct inode local_inode={&local_sb},other_inode={&other_sb};
static struct file original_file={.f_inode=&local_inode,.refs=1,.f_op=&ext4_ops},different_file={.f_inode=&local_inode,.refs=1,.f_op=&ext4_ops},foreign_fs_file={.f_inode=&other_inode,.refs=1,.f_op=&custom_ops};
static void reset(void)
{
 expect(!atomic_read(&sd_active)&&!atomic_read(&sd_bindings)&&!atomic_load(&module_refs),"previous request released state and module references");
 for(unsigned i=0;i<ARRAY_SIZE(sd_calls);i++)expect(!sd_calls[i].first,"no stack request escapes original syscall");
 current=&app;sd_ready=sd_accepting=module_accepting=actor_type_valid=true;reject_during_pin=false;reenter_original=NULL;
 no_extra=named_mode=contents_mode=false;expected_type=8;has_rules=scope_applies=true;sus_path_count=1;hide_name[0]=0;rule_calls=0;
 local_sb.s_magic=EXT4_SUPER_MAGIC;original_file.f_op=different_file.f_op=&ext4_ops;sd_ext4_dir_ops=&ext4_ops;sd_f2fs_dir_ops=&f2fs_ops;sd_call_probe.nmissed=sd_post_probe.nmissed=0;sd_return_probe.nmissed=0;
 sd_call_installed=sd_post_installed=sd_return_installed=false;unregister_count=0;
 atomic_store(&stop_started,false);atomic_store(&stop_finished,false);
}
static struct dir_context context(char *output,size_t capacity)
{
 if(output)memset(output,0,capacity);
 return (struct dir_context){.actor=prior_actor,.cookie=0x12345678UL,.output=output,.capacity=capacity};
}
static void init_context(struct dir_context *ctx,char *output,size_t capacity)
{*ctx=context(output,capacity);ctx->private_data=ctx;}
static void enter_iterator(struct kretprobe_instance *instance,struct file *file,struct dir_context *ctx,unsigned long sp)
{
 struct pt_regs entry={.regs={(unsigned long)file,(unsigned long)ctx},.sp=sp};
 expect(sd_enter(instance,&entry)==0,"original iterate_dir entry records request guard");
}
static void at_call(struct file *file,struct dir_context *ctx,unsigned long entry_sp)
{
 struct pt_regs regs={.regs={(unsigned long)file,(unsigned long)ctx},.sp=entry_sp-SD_STACK_BYTES};
 expect(sd_at_call(&sd_call_probe,&regs)==0,"callsite resumes existing iterator without replay");
}
static void after_call(struct file *file,struct dir_context *ctx,unsigned long entry_sp)
{
 struct pt_regs regs={.sp=entry_sp-SD_STACK_BYTES};regs.regs[19]=(unsigned long)file;regs.regs[SD_CONTEXT_REG]=(unsigned long)ctx;
 expect(sd_after_call(&sd_post_probe,&regs)==0,"postsite resumes original return path");
}
static void return_iterator(struct kretprobe_instance *instance)
{struct pt_regs regs={0};expect(sd_return(instance,&regs)==0,"return recovery finishes original iterator");}
static bool emit(struct dir_context *ctx,const char *name)
{bool rc=ctx->actor(ctx,name,(int)strlen(name),ctx->pos+1,77,8);if(rc)ctx->pos++;return rc;}
static void single_iterator(struct susfs_dirent_call *request,struct dir_context *ctx,bool post)
{
 struct kretprobe_instance instance;enter_iterator(&instance,&original_file,ctx,0x1000);at_call(&original_file,ctx,0x1000);
 expect(ctx->actor==sd_actor&&request->bound,"qualified original actor is temporarily wrapped");
 expect(emit(ctx,"susfs-only")&&emit(ctx,"private-canary")&&emit(ctx,"visible"),"both component filters keep iterator moving");
 if(post)after_call(&original_file,ctx,0x1000);
 return_iterator(&instance);
 expect(ctx->actor==prior_actor&&!request->bound,"same context actor restored before it retires");
}
static void test_scope_and_original(void)
{
 struct task_struct *actors[]={&app,&manager,&root_task};
 for(unsigned i=0;i<ARRAY_SIZE(actors);i++){
  reset();current=actors[i];char output[128];struct dir_context ctx;init_context(&ctx,output,sizeof(output));struct susfs_dirent_call request;
  expect(susfs_dirent_begin(&request,&original_file,false),"qualified ABI/FS admitted regardless of root categorization");single_iterator(&request,&ctx,true);
  expect(susfs_dirent_end(&request),"one complete iterator is covered");
  expect(current->manager?!strcmp(output,"susfs-only\nprivate-canary\nvisible\n"):!strcmp(output,"visible\n"),"existing manager gate and prior private protection both retained");
  expect(rule_calls==3&&ctx.pos==3,"composition delegates each name to existing subject matcher and preserves position");
 }
 reset();scope_applies=false;char output[128];struct dir_context ctx;init_context(&ctx,output,sizeof(output));struct susfs_dirent_call request;
 expect(susfs_dirent_begin(&request,&original_file,false),"non-target request may compose without changing scope");single_iterator(&request,&ctx,true);expect(susfs_dirent_end(&request),"excluded scope remains fully covered");
 expect(!strcmp(output,"susfs-only\nvisible\n"),"non-target subject retains SUSFS object but prior private actor still filters");
 reset();no_extra=true;init_context(&ctx,output,sizeof(output));expect(susfs_dirent_begin(&request,&original_file,false),"no-extra still preserves original chain");single_iterator(&request,&ctx,true);expect(susfs_dirent_end(&request)&&!rule_calls&&!strcmp(output,"susfs-only\nvisible\n"),"actual path no-extra gate disables composition filtering");
}
static void test_name_rule_actor(void)
{
 const unsigned int types[]={0,4,8,10};
 for(unsigned int i=0;i<ARRAY_SIZE(types);i++) {
  reset();named_mode=true;expected_type=types[i];sus_path_count=0;char output[128];
  struct dir_context ctx;struct susfs_dirent_call request;struct kretprobe_instance instance;
  init_context(&ctx,output,sizeof(output));
  expect(susfs_dirent_begin(&request,&original_file,false),"name-only policy uses composed directory actor");
  enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
  expect(ctx.actor(&ctx,"named-only",10,1,77,types[i]),"name-filtered actor continues iteration");
  after_call(&original_file,&ctx,0x1000);return_iterator(&instance);
  expect(susfs_dirent_end(&request),"typed name actor restored completely");
  expect((types[i]==4||types[i]==8)?!output[0]:!strcmp(output,"named-only\n"),
         "composition forwards actual dirent type into name-only matcher");
 }
}
static void test_contents_rule_actor(void)
{
 const unsigned int types[]={0,1,2,4,6,8,10,12};
 for(unsigned i=0;i<ARRAY_SIZE(types);i++) {
  reset();contents_mode=true;expected_type=types[i];char output[128];
  struct dir_context ctx;struct susfs_dirent_call request;struct kretprobe_instance instance;
  init_context(&ctx,output,sizeof(output));
  expect(susfs_dirent_begin(&request,&original_file,false),"contents request uses original held directory");
  enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
  expect(ctx.actor(&ctx,"child",5,1,77,types[i]),"contents mode skips every child type");
  expect(!output[0],"contents mode emits no child name");
  expect(ctx.actor(&ctx,".",1,1,77,types[i])&&ctx.actor(&ctx,"..",2,1,77,types[i]),"dot entries still pass through original actor");
  expect(!strcmp(output,".\n..\n"),"contents mode keeps dot entries and original ordering");
  after_call(&original_file,&ctx,0x1000);return_iterator(&instance);
  expect(susfs_dirent_end(&request),"contents iterator fully restored");
 }
 for(unsigned exempt=0;exempt<2;exempt++) {
  reset();contents_mode=true;if(exempt)current=&manager;else scope_applies=false;
  char output[128];struct dir_context ctx;struct susfs_dirent_call request;struct kretprobe_instance instance;
  init_context(&ctx,output,sizeof(output));expect(susfs_dirent_begin(&request,&original_file,false),"exempt contents request admitted");
  enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
  expect(emit(&ctx,"child")&&!strcmp(output,"child\n"),"exempt contents mode retains child name");
  after_call(&original_file,&ctx,0x1000);return_iterator(&instance);expect(susfs_dirent_end(&request),"exempt request restores original actor");
 }
}
static void test_rejections(void)
{
 struct susfs_dirent_call request;reset();expect(!susfs_dirent_begin(&request,&original_file,true)&&!susfs_dirent_end(&request),"compat always requests explicit fallback");
 expect(!susfs_dirent_begin(&request,&foreign_fs_file,false)&&!susfs_dirent_end(&request),"FUSE source rejects composition");
 other_sb.s_magic=0x794c7630;expect(!susfs_dirent_begin(&request,&foreign_fs_file,false),"overlay source rejects composition");
 expect(!susfs_dirent_begin(&request,NULL,false),"missing held directory rejects composition");
 local_sb.s_magic=F2FS_SUPER_MAGIC;original_file.f_op=&f2fs_ops;expect(susfs_dirent_begin(&request,&original_file,false)&&!susfs_dirent_end(&request),"F2FS eligible but no observed iterator falls back");
 reset();original_file.f_op=&custom_ops;expect(!susfs_dirent_begin(&request,&original_file,false),"custom file operations rejected despite matching filesystem magic");
 reset();sd_ext4_dir_ops=NULL;expect(!susfs_dirent_begin(&request,&original_file,false),"missing standard filesystem operations disables admission");
 reset();sd_ready=false;expect(!susfs_dirent_begin(&request,&original_file,false),"unqualified build falls back");
 reset();module_accepting=false;expect(!susfs_dirent_begin(&request,&original_file,false),"going module rejects request");
 reset();reject_during_pin=true;expect(!susfs_dirent_begin(&request,&original_file,false)&&!atomic_load(&module_refs),"late admission cannot race stop into untracked request");
 reset();char out[32];struct dir_context ctx;init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit request for actual-file mismatch");
 struct kretprobe_instance instance;enter_iterator(&instance,&different_file,&ctx,0x1000);at_call(&different_file,&ctx,0x1000);expect(ctx.actor==prior_actor,"different file description never borrows held-file qualification");return_iterator(&instance);expect(!susfs_dirent_end(&request),"FD reuse mismatch selects fallback");
 reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit actor-type rejection case");enter_iterator(&instance,&original_file,&ctx,0x1000);actor_type_valid=false;at_call(&original_file,&ctx,0x1000);expect(ctx.actor==prior_actor,"wrong actor KCFI type is never installed");return_iterator(&instance);expect(!susfs_dirent_end(&request),"actor-type rejection falls back");
}
static void test_recovery_and_retirement(void)
{
 char out[64];struct dir_context ctx;struct susfs_dirent_call request;reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit return recovery");single_iterator(&request,&ctx,false);expect(susfs_dirent_end(&request),"return guard recovers missed post handler while ctx remains live");
 reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit missing entry guard case");at_call(&original_file,&ctx,0x1000);expect(ctx.actor==prior_actor&&!request.bound,"lost return-entry guard forbids actor mutation");expect(!susfs_dirent_end(&request),"missing entry guard forces fallback");
 for(unsigned i=0;i<3;i++){
  reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit probe-miss counter case");single_iterator(&request,&ctx,true);
  if(i==0)sd_call_probe.nmissed++;else if(i==1)sd_post_probe.nmissed++;else sd_return_probe.nmissed++;
  expect(!susfs_dirent_end(&request),"any probe miss during request forces explicit fallback");
 }
 reset();long page=sysconf(_SC_PAGESIZE);struct dir_context *retired=mmap(NULL,(size_t)page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);expect(retired!=MAP_FAILED,"allocate context retirement fixture");init_context(retired,NULL,0);
 expect(susfs_dirent_begin(&request,&original_file,false),"admit context retirement case");struct kretprobe_instance instance;enter_iterator(&instance,&original_file,retired,0x1000);at_call(&original_file,retired,0x1000);
 expect(!mprotect(retired,(size_t)page,PROT_NONE),"context retires when original returns");
 expect(!susfs_dirent_end(&request),"end reports weak coverage without reading retired context or guard");expect(!munmap(retired,(size_t)page),"release retired test mapping");
 reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit external actor change");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);ctx.actor=foreign_actor;after_call(&original_file,&ctx,0x1000);return_iterator(&instance);
 expect(ctx.actor==foreign_actor&&!susfs_dirent_end(&request),"foreign actor is preserved and coverage degrades");
}
static void nested_inside_original(struct dir_context *ctx)
{
 struct kretprobe_instance nested;struct susfs_dirent_call *outer;
 pthread_mutex_lock(&sd_lock);outer=sd_current_locked();expect(outer&&outer->callbacks==1,"outer original callback remains active during recursive iterator");pthread_mutex_unlock(&sd_lock);
 enter_iterator(&nested,&original_file,ctx,0x0f00);at_call(&original_file,ctx,0x0f00);
 expect(ctx->actor==prior_actor&&!outer->bound&&outer->callbacks==1&&outer->failed,"same-context recursion pauses actor while copied original callback remains valid");
 return_iterator(&nested);
}
static void test_nested_and_multi_iterator(void)
{
 char out[128],out2[128];struct dir_context ctx,inner;struct susfs_dirent_call request;struct kretprobe_instance first,second;
 for(unsigned same=0;same<2;same++){
  reset();init_context(&ctx,out,sizeof(out));init_context(&inner,out2,sizeof(out2));expect(susfs_dirent_begin(&request,&original_file,false),"admit nested iterator case");enter_iterator(&first,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
  struct dir_context *nested=same?&ctx:&inner;enter_iterator(&second,&original_file,nested,0x0f00);at_call(&original_file,nested,0x0f00);expect(!same||(request.original_actor!=sd_actor&&ctx.actor==prior_actor),"same-context nested iterator restores captured original instead of wrapping itself");
  expect(emit(nested,"visible"),"nested unsupported route remains functional");after_call(&original_file,nested,0x0f00);return_iterator(&second);after_call(&original_file,&ctx,0x1000);return_iterator(&first);
  expect(ctx.actor==prior_actor&&inner.actor==prior_actor&&!susfs_dirent_end(&request),"nested iterator restores all reachable actor values and falls back");
 }
 reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit sequential iterator case");single_iterator(&request,&ctx,true);enter_iterator(&second,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);expect(ctx.actor==prior_actor,"second iterator is not falsely counted as fully composed");return_iterator(&second);expect(!susfs_dirent_end(&request),"multiple iterators in one original force fallback");
 reset();init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit recursive callback case");enter_iterator(&first,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);reenter_original=nested_inside_original;expect(emit(&ctx,"visible"),"outer callback completes after nested actor pause");after_call(&original_file,&ctx,0x1000);return_iterator(&first);expect(!request.callbacks&&ctx.actor==prior_actor&&!susfs_dirent_end(&request),"recursive callback releases count and selects fallback without wrapper recursion");
}
static void test_no_user_write_and_false(void)
{
 reset();long page=sysconf(_SC_PAGESIZE);char *none=mmap(NULL,(size_t)page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);expect(none!=MAP_FAILED,"allocate inaccessible output buffer");struct dir_context ctx;init_context(&ctx,NULL,(size_t)page);ctx.output=none;struct susfs_dirent_call request;struct kretprobe_instance instance;
 expect(susfs_dirent_begin(&request,&original_file,false),"admit no-user-write case");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);expect(emit(&ctx,"susfs-only")&&emit(&ctx,"private-canary")&&!ctx.used,"both hidden decisions avoid touching user output");after_call(&original_file,&ctx,0x1000);return_iterator(&instance);expect(susfs_dirent_end(&request),"no-output hidden sequence covered");expect(!munmap(none,(size_t)page),"release inaccessible test buffer");
 reset();char out[8];init_context(&ctx,out,sizeof(out));expect(susfs_dirent_begin(&request,&original_file,false),"admit actor false case");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);expect(emit(&ctx,"first")&&!emit(&ctx,"second")&&!emit(&ctx,"io-error"),"original false return on full buffer and error is preserved");after_call(&original_file,&ctx,0x1000);return_iterator(&instance);expect(susfs_dirent_end(&request)&&!strcmp(out,"first\n"),"false return is normal covered iteration termination");
}
static void *stop_thread(void *ignored)
{(void)ignored;susfs_dirent_stop();atomic_store(&stop_finished,true);return NULL;}
static void test_stop_drain(void)
{
 reset();sd_call_installed=sd_post_installed=sd_return_installed=true;
 struct susfs_dirent_call request,rejected;expect(susfs_dirent_begin(&request,&original_file,false),"admit request before stop");
 pthread_t thread;expect(!pthread_create(&thread,NULL,stop_thread,NULL),"start lifecycle stop");
 while(!atomic_load(&stop_started))sched_yield();
 expect(!atomic_load(&stop_finished)&&sd_post_installed&&sd_return_installed,"sleeping original retains recovery probes while stop waits");
 expect(!susfs_dirent_begin(&rejected,&original_file,false),"stop rejects new requests before waiting");
 expect(!susfs_dirent_end(&request),"empty active request ends and wakes stop");expect(!pthread_join(thread,NULL),"join completed stop");
 expect(atomic_load(&stop_finished)&&unregister_count==3&&unregister_order[0]==1&&unregister_order[1]==2&&unregister_order[2]==3,"stop removes callsite first and recovery probes only after drain");
}
static void test_bound_names_and_capacity(void)
{
 reset();const char bounded[]={'s','u','s','f','s','-','o','n','l','y','X'};
 expect(sus_path_dirent_hidden_n(&local_sb,77,bounded,10),"real bounded-name helper accepts nonterminated filesystem name");
 expect(!sus_path_dirent_hidden_n(&local_sb,77,"susfs/only",10),"slash in directory entry never matches path policy");
 expect(!sus_path_dirent_hidden_n(&local_sb,77,"susfs\0only",10),"embedded nul is rejected before C-string matcher");
 expect(!sus_path_dirent_hidden_n(&local_sb,77,(const char *)1,256),"overlong name rejected without dereferencing bytes");
 struct susfs_dirent_call calls[SD_MAX_BUCKET_CALLS+1];
 struct {struct task_struct task;char padding[1024-sizeof(struct task_struct)];} tasks[SD_MAX_BUCKET_CALLS+1];
 for(unsigned i=0;i<SD_MAX_BUCKET_CALLS;i++){tasks[i].task=app;current=&tasks[i].task;expect(susfs_dirent_begin(calls+i,&original_file,false),"bounded request bucket admits available slots from distinct colliding tasks");}
 tasks[SD_MAX_BUCKET_CALLS].task=app;current=&tasks[SD_MAX_BUCKET_CALLS].task;
 expect(!susfs_dirent_begin(calls+SD_MAX_BUCKET_CALLS,&original_file,false),"saturated request bucket safely requests fallback");
 for(unsigned i=SD_MAX_BUCKET_CALLS;i>0;i--){current=&tasks[i-1].task;expect(!susfs_dirent_end(calls+i-1),"capacity requests all unlink before stack exit");}
 reset();char output[32];struct dir_context ctx;init_context(&ctx,output,sizeof(output));struct susfs_dirent_call request;struct kretprobe_instance instance;
 expect(susfs_dirent_begin(&request,&original_file,false),"admit wrong stack-frame case");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1004);expect(ctx.actor==prior_actor,"wrong stack pointer never captures actor from another invocation");return_iterator(&instance);expect(!susfs_dirent_end(&request),"wrong stack frame falls back");
 reset();init_context(&ctx,output,sizeof(output));expect(susfs_dirent_begin(&request,&original_file,false),"admit changed operations case");enter_iterator(&instance,&original_file,&ctx,0x1000);original_file.f_op=&custom_ops;at_call(&original_file,&ctx,0x1000);expect(ctx.actor==prior_actor,"callsite rechecks actual filesystem operations before mutation");return_iterator(&instance);expect(!susfs_dirent_end(&request),"operations change selects fallback");
 reset();init_context(&ctx,output,sizeof(output));expect(susfs_dirent_begin(&request,&original_file,false),"admit outer original syscall request");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
 struct susfs_dirent_call inner_request;struct kretprobe_instance nested;
 expect(!susfs_dirent_begin(&inner_request,&different_file,false)&&request.failed,"recursive syscall begin cannot shadow outer bound context with another request");
 enter_iterator(&nested,&original_file,&ctx,0x0f00);at_call(&original_file,&ctx,0x0f00);expect(ctx.actor==prior_actor&&!request.bound,"recursive same-context iterator pauses outer binding before forwarding");return_iterator(&nested);expect(!susfs_dirent_end(&inner_request),"inactive recursive request safely requests fallback");after_call(&original_file,&ctx,0x1000);return_iterator(&instance);expect(!susfs_dirent_end(&request),"outer request degrades after recursive request attempt");
}
static atomic_bool blocked_request_finished;
static void *sleeping_request(void *unused)
{
 (void)unused;current=&app;char output[64];struct dir_context ctx;init_context(&ctx,output,sizeof(output));ctx.block=true;
 struct susfs_dirent_call request;struct kretprobe_instance instance;
 expect(susfs_dirent_begin(&request,&original_file,false),"admit sleeping original request");enter_iterator(&instance,&original_file,&ctx,0x1000);at_call(&original_file,&ctx,0x1000);
 expect(emit(&ctx,"visible"),"sleeping original actor can finish after stop requested");after_call(&original_file,&ctx,0x1000);return_iterator(&instance);expect(susfs_dirent_end(&request),"in-progress composition restores and finishes while admission stopped");
 atomic_store(&blocked_request_finished,true);return NULL;
}
static void test_sleeping_actor_stop(void)
{
 reset();sd_call_installed=sd_post_installed=sd_return_installed=true;
 pthread_mutex_lock(&block_lock);original_entered=original_released=false;pthread_mutex_unlock(&block_lock);atomic_store(&blocked_request_finished,false);
 pthread_t worker,stopper;expect(!pthread_create(&worker,NULL,sleeping_request,NULL),"start real blocking actor fixture");
 pthread_mutex_lock(&block_lock);while(!original_entered)pthread_cond_wait(&block_cond,&block_lock);pthread_mutex_unlock(&block_lock);
 expect(atomic_read(&sd_active)==1&&atomic_read(&sd_bindings)==1&&atomic_load(&module_refs)==1,"sleeping original retains request, bound actor and module pin");
 expect(!pthread_create(&stopper,NULL,stop_thread,NULL),"stop while original actor is asleep");while(!atomic_load(&stop_started))sched_yield();
 expect(!atomic_load(&stop_finished)&&!atomic_load(&blocked_request_finished),"stop cannot remove recovery while callback sleeps");
 pthread_mutex_lock(&block_lock);original_released=true;pthread_cond_broadcast(&block_cond);pthread_mutex_unlock(&block_lock);
 expect(!pthread_join(worker,NULL)&&!pthread_join(stopper,NULL),"sleeping actor restores before shutdown completion");
 expect(atomic_load(&stop_finished)&&atomic_load(&blocked_request_finished)&&!atomic_load(&module_refs),"no callback or module reference escapes draining shutdown");
}
int main(void)
{
 test_scope_and_original();test_name_rule_actor();test_contents_rule_actor();test_rejections();test_recovery_and_retirement();test_nested_and_multi_iterator();test_no_user_write_and_false();test_bound_names_and_capacity();test_stop_drain();test_sleeping_actor_stop();reset();
 printf("DIRENT_COMPOSE_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",atomic_load(&checks));return 0;
}
'''


def definition(source: str, name: str) -> str:
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = rf"^(?:static\s+)?(?:inline\s+)?(?:__nocfi\s+)?(?:noinline\s+)?(?:bool|int|void|struct\s+susfs_dirent_call\s*\*)\s*{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one production definition for {name}, got {len(matches)}")
    start, depth = matches[0].start(), 0
    for cursor in range(masked.index("{", start), len(masked)):
        depth += (masked[cursor] == "{") - (masked[cursor] == "}")
        if not depth:
            return source[start:cursor + 1]
    raise ValueError(f"unbalanced production definition {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--kernel-version", choices=["6.6", "6.12"], default="6.12")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    source_path = repo / "kernel/sus_dirent.c"
    source = source_path.read_text(encoding="utf-8")
    header_path = repo / "kernel/susfs_dirent.h"
    path_source_file = repo / "kernel/sus_path.c"
    path_source = path_source_file.read_text(encoding="utf-8")
    names = ["sd_current_locked", "sd_bound_locked", "sd_local_file", "susfs_dirent_composed_ready", "susfs_dirent_begin",
             "sd_set_actor", "sd_restore_locked", "sd_pause_nested_locked", "susfs_dirent_end", "sd_call_actor", "sd_actor", "sd_enter",
             "sd_actor_qualified", "sd_at_call", "sd_after_call", "sd_return", "susfs_dirent_stop"]
    pieces = {name: definition(source, name) for name in names}
    pieces["susfs_dirent_call"] = extract(header_path.read_text(encoding="utf-8"), "susfs_dirent_call", structure=True)
    pieces["susfs_dirent_guard"] = extract(source, "susfs_dirent_guard", structure=True)
    paths = {name: definition(path_source, name) for name in ["sus_path_dirent_hidden", "sus_path_dirent_hidden_n"]}
    layout = source[source.index("#if LINUX_VERSION_CODE"):source.index("#define SD_MAXACTIVE")]
    constants = re.findall(r"^#define SD_[A-Z_0-9]+[^\n]*", source[source.index("#define SD_MAXACTIVE"):], re.M)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    generated = evidence / "dirent-compose-extracted.c"
    generated.write_text(PREAMBLE + "\n" + layout + "\n" + "\n".join(constants) + "\n" + pieces["susfs_dirent_call"] + "\n" +
                         pieces["susfs_dirent_guard"] + GLOBALS + "\n" + "\n".join(paths.values()) + "\n" +
                         "\n\n".join(pieces[name] for name in names) + TESTS, encoding="utf-8")
    receipt = {"kernel_calls": False, "kernel_version": args.kernel_version, "production_source": "kernel/sus_dirent.c",
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "additional_source_sha256": {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
                                            for path in [header_path, path_source_file]},
               "extracted_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in {**pieces, **paths}.items()},
               "limits": "Actual production bodies with typed probe/CFI/VFS/subject-boundary doubles; not kernel or device validation.", "runs": []}
    for label, flags in [("strict", ["-O2"]), ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("dirent-compose-" + label + ".bin")
        build = execute([args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", *flags,
                         "-pthread", "-DTEST_KERNEL_VERSION=" + ("0x060600" if args.kernel_version == "6.6" else "0x060c00"),
                         execution_path(generated), "-o", execution_path(binary)])
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"DIRENT_COMPOSE_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "dirent-compose-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
