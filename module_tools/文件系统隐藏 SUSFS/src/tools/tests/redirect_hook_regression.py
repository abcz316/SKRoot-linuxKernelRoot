#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise extracted production redirect lookup, reporting and writer code.

Typed host doubles validate copies, formatting, ref cleanup and lock ordering;
they do not establish actual kernel/VFS/RCU/probe or device behavior.
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
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include "skp_full_objects.h"
#include "susfs_abi.h"
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t test_dev_t;
#define dev_t test_dev_t
#define __nocfi
#define noinline
#define __user
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_rmb() ((void)0)
#define smp_wmb() ((void)0)
#define BUILD_BUG_ON(x) _Static_assert(!(x), "production build guard")
#define BITS_PER_LONG 64
#define SUS_OR_MAX 64
#define OR_PATH_MAX 256
#define FUSE_SUPER_MAGIC 0x65735546
#define MAJOR(d) ((unsigned int)(d) >> 20)
#define MINOR(d) ((unsigned int)(d) & 0xfffffU)
#define LOOKUP_FOLLOW 1U
#define LOOKUP_DIRECTORY 2U
#define LOOKUP_NO_XDEV 4U
#define LOOKUP_NO_MAGICLINKS 8U
#define LOOKUP_NO_SYMLINKS 16U
#define LOOKUP_BENEATH 32U
#define LOOKUP_IN_ROOT 64U
#define LOOKUP_CACHED 128U
#define SUSFS_RESOLVE_NO_XDEV 1U
#define SUSFS_RESOLVE_NO_MAGICLINKS 2U
#define SUSFS_RESOLVE_NO_SYMLINKS 4U
#define SUSFS_RESOLVE_BENEATH 8U
#define SUSFS_RESOLVE_IN_ROOT 16U
#define SUSFS_RESOLVE_CACHED 32U
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
enum susfs_or_entry_kind {
 SUSFS_OR_ENTRY_OPENAT=0,SUSFS_OR_ENTRY_OPENAT2,SUSFS_OR_ENTRY_COMPAT_OPEN,
 SUSFS_OR_ENTRY_COMPAT_OPENAT,SUSFS_OR_ENTRY_COMPAT_OPENAT2,SUSFS_OR_ENTRY_KIND_COUNT
};
#define __NR_openat2 437
struct test_lock { bool held; };
static struct test_lock or_lock;
static unsigned int checks;
static void expect(bool c, const char *message)
{ ++checks; if (!c) { fprintf(stderr,"FAIL check=%u %s\n",checks,message); exit(1); } }
static void mutex_lock(struct test_lock *l)
{ expect(!l->held,"writer mutex is nonrecursive"); l->held=true; }
static void mutex_unlock(struct test_lock *l)
{ expect(l->held,"unlock owned writer mutex"); l->held=false; }
#define lockdep_assert_held(l) expect((l)->held,"writer owns family mutex")
static bool test_warn(bool x) { expect(!x,"production invariant");return x; }
#define WARN_ON_ONCE(x) test_warn(x)
#define pr_warn(...) ((void)0)
#define SUSFS_LOGI(...) ((void)0)
typedef struct { unsigned int value; } atomic_t;
static void atomic_inc(atomic_t *a) { a->value++; }
static long strscpy(char *dst,const char *src,size_t n)
{ size_t z=strlen(src); if (!n) return -E2BIG; if (z>=n) { memcpy(dst,src,n-1);dst[n-1]=0;return -E2BIG; } memcpy(dst,src,z+1);return (long)z; }
static int scnprintf(char *dst,size_t n,const char *fmt,...)
{ va_list ap;va_start(ap,fmt);int z=vsnprintf(dst,n,fmt,ap);va_end(ap);return z<0?0:((size_t)z<n?z:(int)n-1); }
struct super_block { dev_t s_dev; unsigned long s_magic; };
struct inode { struct super_block *i_sb; unsigned long i_ino; unsigned int i_generation; };
struct dentry { struct inode *inode; struct dentry *d_parent; struct { const char *name; } d_name; };
struct vfsmount { int mnt_id; unsigned int refs; };
struct path { struct dentry *dentry; struct vfsmount *mnt; };
#define real_mount(p) (p)
static struct inode *d_inode(struct dentry *d) { return d->inode; }
static struct inode *d_backing_inode(struct dentry *d) { return d->inode; }
struct file { struct path f_path; };
static struct inode *file_inode(struct file *f) { return f->f_path.dentry->inode; }
struct seq_file { char *buf;size_t count,size;struct file *file; };
struct vm_area_struct { struct file *vm_file; };
struct kstatfs { unsigned long value[16]; };
struct pt_regs { unsigned long regs[8]; };
struct kretprobe_instance { void *data; };
#define regs_return_value(r) ((r)->regs[0])
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
static bool susfs_ptr_plausible(const void *p) { return p!=NULL&&!IS_ERR(p); }
static bool grouped, legacy_gate, upstream_gate=true;
static bool exiting_ready=true, fail_register;
static enum skp_object_query_mode query_mode;
static struct skp_redirect_query_result {
 u32 matched,legacy_allowed;u64 generation;char path[256],target_path[256];
 u64 source_dev,source_ino,source_mnt_id;struct kstatfs source_statfs;
} query_answer;
static struct skp_fdinfo_query_result fdinfo_answer;
static unsigned int redirect_queries,fdinfo_queries,reverse_arms;
static u64 query_dev,query_ino,query_mnt;
static u32 query_gen,query_direction;
static enum skp_object_query_mode skp_policy_redirect_query(u64 dev,u64 ino,u32 gen,u64 mnt,u32 direction,
 struct skp_redirect_query_result *out)
{ query_dev=dev;query_ino=ino;query_gen=gen;query_mnt=mnt;query_direction=direction;++redirect_queries;*out=query_answer;out->legacy_allowed=legacy_gate;return query_mode; }
static enum skp_object_query_mode skp_policy_fdinfo_query(u64 ino,u64 mnt,struct skp_fdinfo_query_result *out)
{ query_ino=ino;query_mnt=mnt;++fdinfo_queries;*out=fdinfo_answer;out->legacy_allowed=legacy_gate;return query_mode; }
static bool skp_policy_paths_active(void) { return grouped; }
static bool skp_policy_redirects_active(void) { return grouped&&query_answer.matched; }
static bool susfs_is_current_proc_umounted_app(void) { return upstream_gate; }
static bool susfs_is_current_proc_umounted(void) { return upstream_gate; }
static bool or_in_su_domain(void) { return false; }
typedef struct { unsigned int val; } kuid_t;
static unsigned int test_uid;
static kuid_t current_uid(void) { return (kuid_t){test_uid}; }
static int copy_from_user(void *dst,const void *src,size_t n) { memcpy(dst,src,n);return 0; }
static int kstrtol(const char *s,unsigned int base,long *out)
{ char *end;errno=0;*out=strtol(s,&end,(int)base);return errno||*end?-EINVAL:0; }
static bool susfs_abi_path_ok(const char *p,size_t cap) { return p&&p[0]&&strnlen(p,cap)<cap; }
static void synchronize_rcu(void) { }
static unsigned int rcu_depth;
static void rcu_read_lock(void) { ++rcu_depth; }
static void rcu_read_unlock(void) { expect(rcu_depth>0,"RCU nesting");--rcu_depth; }
static unsigned int live_paths,path_calls,put_calls,sample_calls,mnt_gets,resolve_fail;
static bool sample_fail,change_group_after_resolve;
static struct super_block src_sb={0x800001U,0},dst_sb={0x900002U,0};
static struct inode src_inode={&src_sb,123,10},dst_inode={&dst_sb,456,20};
static struct dentry src_dentry={&src_inode,NULL,{"source"}},dst_dentry={&dst_inode,NULL,{"target"}};
static struct vfsmount src_mount={71,0},dst_mount={81,0};
static int kern_path(const char *name,unsigned int flags,struct path *out)
{
 expect(!or_lock.held,"VFS lookup occurs outside redirect mutex");expect(flags==LOOKUP_FOLLOW,"resolver follows links");
 ++path_calls;if (resolve_fail==path_calls)return -ENOENT;
 if (!strcmp(name,"/source")) *out=(struct path){&src_dentry,&src_mount};
 else *out=(struct path){&dst_dentry,&dst_mount};
 ++live_paths;return 0;
}
static void path_put(struct path *p)
{ expect(!or_lock.held,"path_put occurs outside redirect mutex");expect(p->dentry&&live_paths,"path reference owned");--live_paths;++put_calls;if(change_group_after_resolve)grouped=true; }
static struct vfsmount *mntget(struct vfsmount *m)
{ ++m->refs;++mnt_gets;return m; }
static int or_statfs_snapshot(const struct path *p,struct kstatfs *out)
{ expect(!or_lock.held,"statfs sampling outside redirect mutex");expect(p->dentry==&src_dentry,"source statfs sampled");++sample_calls;if(sample_fail)return -EIO;out->value[0]=99;return 0; }
static unsigned int or_su_sid=4;
static void or_resolve_su_sid(void) { }
static bool or_exiting,or_registered,or_dpath_registered,or_statfs_registered,or_maps_registered;
static int n_or_fdinfo_probes;
static bool susfs_or_entry_armed(void) { return exiting_ready&&!fail_register; }
static void or_register_reverse(void) { ++reverse_arms; }
static bool or_entry_ready=true;
static void susfs_opath_openat(void) { }
static void susfs_opath_openat2(void) { }
static void susfs_opath_compat_openat2(void) { }
static void susfs_opath_compat_open(void) { }
static void susfs_opath_compat_openat(void) { }
struct susfs_fp_hook { bool installed;void (*wrapper)(void); };
static struct susfs_fp_hook opath_hooks[]={
 {true,susfs_opath_openat},{true,susfs_opath_openat2},{true,susfs_opath_compat_openat2},
 {true,susfs_opath_compat_open},{true,susfs_opath_compat_openat}
};
unsigned int susfs_opath_open_routes(void);
unsigned int susfs_or_entry_routes(void);
static atomic_t or_rev_dpath_hits,or_rev_statfs_hits,or_rev_maps_hits,or_rev_maps_rewrites,or_rev_maps_names;
static atomic_t or_rev_fdinfo_hits,or_rev_fdinfo_rewrites;
'''

GLOBALS = r'''
static struct sus_or_entry or_entries[SUS_OR_MAX];
static int nor;
static unsigned int or_free[SUS_OR_MAX],or_free_n,susfs_open_redirect_rules;
static void or_reclaim_slot(struct sus_or_entry *entry);
'''

TESTS = r'''
static void reset(void)
{
 expect(!or_lock.held&&!rcu_depth&&!live_paths&&!src_mount.refs&&!dst_mount.refs,"test reset owns no locks or refs");
 memset(or_entries,0,sizeof(or_entries));for(size_t i=0;i<SUS_OR_MAX;i++)or_entries[i].dead=true;
 nor=0;or_free_n=0;susfs_open_redirect_rules=0;grouped=false;legacy_gate=false;upstream_gate=true;test_uid=0;
 query_mode=SKP_OBJECT_UPSTREAM;memset(&query_answer,0,sizeof(query_answer));memset(&fdinfo_answer,0,sizeof(fdinfo_answer));
 or_exiting=false;or_registered=false;exiting_ready=true;fail_register=false;reverse_arms=0;or_entry_ready=true;
 for(size_t i=0;i<ARRAY_SIZE(opath_hooks);i++)opath_hooks[i].installed=true;
 or_dpath_registered=or_statfs_registered=or_maps_registered=false;n_or_fdinfo_probes=0;
 resolve_fail=path_calls=put_calls=sample_calls=mnt_gets=0;sample_fail=change_group_after_resolve=false;
 src_dentry.inode=&src_inode;dst_dentry.inode=&dst_inode;src_sb.s_magic=dst_sb.s_magic=0;src_mount.refs=dst_mount.refs=0;
 redirect_queries=fdinfo_queries=0;
}
static void grouped_answer(void)
{
 grouped=true;query_mode=SKP_OBJECT_GROUPED;query_answer.matched=1;
 strcpy(query_answer.path,"/visible");strcpy(query_answer.target_path,"/actual");
 query_answer.source_dev=0xa00003U;query_answer.source_ino=999;query_answer.source_mnt_id=70;
 query_answer.source_statfs.value[0]=777;
}
static void lookups(void)
{
 struct path p={&src_dentry,&src_mount};char out[256];struct skp_redirect_query_result r;
 reset();grouped_answer();expect(nor==0&&susfs_open_redirect_active(),"group rules active with empty old table");
 expect(susfs_open_redirect_match_path(&p,out,sizeof(out))&&!strcmp(out,"/visible"),"grouped forward copied string");
 expect(query_dev==src_sb.s_dev&&query_ino==src_inode.i_ino&&query_gen==src_inode.i_generation&&query_direction==SKP_REDIRECT_FORWARD,"forward passes raw source identity");
 expect(!susfs_open_redirect_match_path(&p,out,2),"small forward buffer refuses match");
 expect(or_reverse_lookup(&src_inode,&r)&&r.source_ino==999&&r.source_statfs.value[0]==777,"group reverse copies values");
 expect(query_gen==src_inode.i_generation&&query_direction==SKP_REDIRECT_REVERSE,"reverse query uses identity with generation");
 query_answer.matched=0;expect(!susfs_open_redirect_match_path(&p,out,sizeof(out)),"group miss authoritative");
 expect(!or_reverse_lookup(&src_inode,&r),"group reverse miss authoritative");
 unsigned long ino=0,mnt=0;expect(!susfs_open_redirect_spoof_ids(456,&ino,&mnt),"old inode-only helper never guesses group");
 reset();expect(or_add("/source","/target",UID_NON_APP_PROC)==0,"legacy add prepares detached then commits");
 expect(!live_paths&&sample_calls==1&&susfs_open_redirect_rules==1,"legacy keeps no resolved refs");
 expect(susfs_open_redirect_match_path(&p,out,sizeof(out))&&!strcmp(out,"/target"),"upstream forward works");
 query_mode=SKP_OBJECT_LEGACY_SUBJECT;legacy_gate=false;
 expect(!susfs_open_redirect_match_path(&p,out,sizeof(out)),"copied legacy subject deny");legacy_gate=true;upstream_gate=false;
 expect(susfs_open_redirect_match_path(&p,out,sizeof(out)),"legacy subject allow bypasses upstream predicate");
 expect(or_reverse_lookup(&dst_inode,&r)&&r.source_ino==123,"legacy reverse uses copied allow");
 query_mode=SKP_OBJECT_GROUPED;query_answer.matched=0;
 expect(!susfs_open_redirect_match_path(&p,out,sizeof(out))&&!or_reverse_lookup(&dst_inode,&r),"legacy entries cannot leak into group miss");
}
static void reports(void)
{
 char data[1024]="previous 09:02 123 /actual\n";
 struct file opened={{&dst_dentry,&dst_mount}};struct vm_area_struct vma={&opened};
 struct seq_file m={data,strlen(data),sizeof(data),NULL};
 struct or_maps_args maps;struct kretprobe_instance ri={&maps};
 struct pt_regs regs={{(unsigned long)&m,(unsigned long)&vma}};
 reset();grouped_answer();or_maps_entry(&ri,&regs);
 size_t before=m.count;or_maps_ret(&ri,&regs);expect(m.count==before&&!strcmp(data,"previous 09:02 123 /actual\n"),"skipped map cannot rewrite prior line");
 strcat(data,"new 09:02 456 /actual\n");m.count=strlen(data);or_maps_ret(&ri,&regs);
 data[m.count]=0;expect(!strncmp(data,"previous 09:02 123 /actual\n",before)&&strstr(data+before,"0a:03 999 /visible"),"maps only rewrites appended interval");
 before=m.count;expect(!or_buf_replace(&m,m.count,"09",2,"0a",2)&&m.count==before,"empty interval refuses rewrite");
 struct or_dpath_args da;ri.data=&da;regs.regs[0]=(unsigned long)&opened.f_path;regs.regs[1]=(unsigned long)data;regs.regs[2]=sizeof(data);
 or_dpath_entry(&ri,&regs);strcpy(query_answer.path,"/changed");strcpy(data,"/actual");regs.regs[0]=(unsigned long)(data+2);
 or_dpath_ret(&ri,&regs);expect(regs.regs[0]==(unsigned long)(data+sizeof(data)-sizeof("/visible"))&&!strcmp((char *)regs.regs[0],"/visible"),"dpath entry keeps tail-placed copy across config mutation");
 strcpy(query_answer.path,"/visible");struct or_statfs_args sa;struct kstatfs stats={{2}};ri.data=&sa;
 regs.regs[0]=(unsigned long)&opened.f_path;regs.regs[1]=(unsigned long)&stats;or_statfs_entry(&ri,&regs);
 query_answer.source_statfs.value[0]=888;regs.regs[0]=0;or_statfs_ret(&ri,&regs);
 expect(stats.value[0]==777,"statfs snapshot copied before return");
 regs.regs[0]=(unsigned long)-EIO;stats.value[0]=2;or_statfs_ret(&ri,&regs);expect(stats.value[0]==2,"failed statfs retains real failure");
 struct dentry parent={NULL,NULL,{"fdinfo"}},fdentry={NULL,&parent,{"7"}};struct file proc={{&fdentry,NULL}};
 strcpy(data,"pos:\t0\nflags:\t0\nmnt_id:\t81\nino:\t456\n");m.count=strlen(data);m.file=&proc;
 struct seq_file *slot=&m;ri.data=&slot;regs.regs[0]=0;fdinfo_answer.rewrite_ino=1;fdinfo_answer.ino=123;fdinfo_answer.mnt_id=70;
 or_fdinfo_ret(&ri,&regs);data[m.count]=0;expect(strstr(data,"mnt_id:\t70\n")&&strstr(data,"ino:\t123\n"),"fdinfo one query updates both values");
 expect(fdinfo_queries==1,"fdinfo uses one generation query");
 expect(query_ino==456&&query_mnt==81,"fdinfo supplies actual inode and mount together");
 strcpy(data,"mnt_id:\t81\nino:\t456\n");m.count=strlen(data);fdinfo_answer.rewrite_ino=0;fdinfo_answer.mnt_id=7;
 or_fdinfo_ret(&ri,&regs);data[m.count]=0;expect(strstr(data,"mnt_id:\t7\n")&&strstr(data,"ino:\t456\n"),"fdinfo mount-only works with no inode rewrite");
 size_t pos,len;unsigned long value;strcpy(data,"ino:\t18446744073709551616\n");m.count=strlen(data);
 expect(!or_fdinfo_find_dec(&m,"ino:\t",5,&pos,&len,&value),"overflow decimal cannot alias a rule");
}
static void resolver(void)
{
 struct skp_group_redirect_object object;struct kstatfs stats;struct vfsmount *a,*b;
 for(unsigned int mode=0;mode<9;mode++) {
  reset();memset(&object,0x6a,sizeof(object));memset(&stats,0,sizeof(stats));a=b=(void *)(uintptr_t)1;
  if(mode==1)resolve_fail=1;
  if(mode==2)resolve_fail=2;
  if(mode==3)src_dentry.inode=NULL;
  if(mode==4)dst_dentry.inode=NULL;
  if(mode==5)src_sb.s_magic=FUSE_SUPER_MAGIC;
  if(mode==6)dst_sb.s_magic=FUSE_SUPER_MAGIC;
  if(mode==7)sample_fail=true;
  if(mode==8)src_sb.s_magic=dst_sb.s_magic=FUSE_SUPER_MAGIC;
  int result=susfs_open_redirect_resolve_group("/source","/target",&object,&stats,&a,&b);
  expect(!live_paths,"resolver releases every temporary path");
  if(!mode||mode==6||mode==7){ expect(!result&&object.source.dev==src_sb.s_dev&&object.source.ino==123&&object.source.igen==10&&object.target.dev==dst_sb.s_dev&&object.target.ino==456&&object.target.igen==20&&object.source_mnt_id==71&&object.target_mnt_id==81,"group resolves exact identities including FUSE target");
   expect(a==&src_mount&&b==&dst_mount&&a->refs==1&&b->refs==1&&stats.value[0]==(mode==7?0:99),"prepare-only mount refs and optional statfs result explicitly returned");--a->refs;--b->refs; }
  else expect(result<0&&a==NULL&&b==NULL&&object.profile_id==0x6a6a6a6aU,"failure leaves no refs or partial outputs");
 }
 for(unsigned int ends=1;ends<4;ends++) {
  reset();if(ends&1)src_sb.s_magic=FUSE_SUPER_MAGIC;if(ends&2)dst_sb.s_magic=FUSE_SUPER_MAGIC;
  expect(or_add("/source","/target",UID_NON_APP_PROC)==-EINVAL&&!nor&&!susfs_open_redirect_rules&&!live_paths&&!src_mount.refs&&!dst_mount.refs,"legacy FUSE rejection unchanged at either end");
 }
 reset();dst_sb.s_magic=FUSE_SUPER_MAGIC;
 expect(!susfs_open_redirect_resolve_group("/source","/target",&object,&stats,NULL,NULL)&&!live_paths&&!src_mount.refs&&!dst_mount.refs,"FUSE target resolution without requested mount refs retains none");
 reset();sample_fail=true;expect(!or_add("/source","/target",UID_NON_APP_PROC)&&!live_paths,"upstream legacy keeps optional statfs degradation");
 reset();change_group_after_resolve=true;expect(or_add("/source","/target",UID_NON_APP_PROC)==-EBUSY&&!nor,"group ownership rechecked after sleeping prepare");
 reset();grouped=true;expect(or_add("/source","/target",UID_NON_APP_PROC)==-EBUSY&&!path_calls,"group writer deny before resolve");
 reset();fail_register=true;expect(or_add("/source","/target",UID_NON_APP_PROC)==-ENODEV&&!nor&&!live_paths,"failed forward arm commits no rule");
 reset();for(unsigned int i=0;i<100;i++)expect(!or_add("/source","/target",UID_NON_APP_PROC),"legacy replacing reclaims slot");
 expect(nor==1&&susfs_open_redirect_rules==1,"replacement live count stable");
}
static void routes(void)
{
 reset();susfs_open_redirect_group_write_begin();
 expect(!susfs_open_redirect_group_prepare_locked(true)&&reverse_arms==1&&!nor&&or_registered,"first grouped rule arms with old count zero");
 susfs_open_redirect_group_write_end();
 reset();fail_register=true;susfs_open_redirect_group_write_begin();
 expect(susfs_open_redirect_group_prepare_locked(true)==-ENODEV&&!reverse_arms,"absent forward rejects redirect group");
 expect(!susfs_open_redirect_group_prepare_locked(false)&&reverse_arms==1,"mount-only fdinfo does not need forward entry");
 susfs_open_redirect_group_write_end();
 reset();
 expect(susfs_opath_open_routes()==31,"all five installed syscall routes exported");
 for(size_t i=0;i<ARRAY_SIZE(opath_hooks);i++)opath_hooks[i].installed=false;
 expect(!susfs_or_entry_routes(),"no installed syscall wrapper means no route");
 opath_hooks[4].installed=true;
 expect(susfs_opath_open_routes()==(1U<<SUSFS_OR_ENTRY_COMPAT_OPENAT),"compat route mapped by actual wrapper");
 or_entry_ready=false;expect(!susfs_or_entry_routes(),"unresolved helper set advertises no routes");or_entry_ready=true;
 or_dpath_registered=true;or_statfs_registered=true;or_maps_registered=true;n_or_fdinfo_probes=2;
 expect(susfs_open_redirect_group_routes()==((1U<<3)|(15U<<8)),"forward and reverse capabilities independent");
 expect((or_lookup_flags(O_NOFOLLOW,0)&LOOKUP_FOLLOW)==0,"NOFOLLOW lookup remains unfollowed");
 expect((or_lookup_flags(O_CREAT|O_EXCL,0)&LOOKUP_FOLLOW)==0,"exclusive create retains link behavior");
 expect(or_lookup_flags(O_RDONLY,0)&LOOKUP_FOLLOW,"ordinary opens follow source links");
 expect((or_lookup_flags(O_DIRECTORY,SUSFS_RESOLVE_NO_XDEV|SUSFS_RESOLVE_BENEATH)&(LOOKUP_DIRECTORY|LOOKUP_NO_XDEV|LOOKUP_BENEATH))==(LOOKUP_DIRECTORY|LOOKUP_NO_XDEV|LOOKUP_BENEATH),"openat2 source flags mapped unchanged");
}
static void writers(void)
{
 reset();struct file file={0};loff_t position=0;
 const char *add="add_open_redirect /source /target 0";
 expect(or_proc_write(&file,add,strlen(add),&position)==(ssize_t)strlen(add),"proc add resolves outside mutex");
 grouped=true;
 expect(or_proc_write(&file,"del /source",11,&position)==-EBUSY&&susfs_open_redirect_rules==1,"group mode blocks old proc delete");
 expect(or_proc_write(&file,"clear",5,&position)==-EBUSY&&susfs_open_redirect_rules==1,"group mode blocks old proc clear");
 grouped=false;
 expect(or_proc_write(&file,"del /source",11,&position)==11&&!susfs_open_redirect_rules,"legacy delete reclaims rule");
 expect(or_proc_write(&file,add,strlen(add),&position)==(ssize_t)strlen(add),"reclaimed proc slot reusable");
 expect(or_proc_write(&file,"clear",5,&position)==5&&!susfs_open_redirect_rules,"legacy clear releases rule");
 const char *large="add_open_redirect /source /target 4294967296";
 expect(or_proc_write(&file,large,strlen(large),&position)==-EINVAL,"scheme cannot narrow-wrap into valid enum");
 test_uid=10001;
 expect(or_proc_write(&file,add,strlen(add),&position)==-ENOENT,"privilege checked on each old proc write");
}
int main(void)
{
 lookups();reports();resolver();routes();writers();
 printf("REDIRECT_HOOK_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",checks);
 return 0;
}
'''


def definition(source: str, name: str, structure: bool = False) -> str:
    if structure:
        return extract(source, name, structure=True)
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    pattern = rf"^(?:static\s+)?(?:bool|int|void|u32|unsigned\s+int|ssize_t|struct\s+sus_or_entry\s*\*)\s*{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, masked, flags=re.M))
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
    parser.add_argument("--mutation", choices=["none", "map-interval", "writer-recheck", "group-fallback"], default="none")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/susfs_open_redirect.c"
    source = source_path.read_text(encoding="utf-8")
    structs = ["sus_or_entry", "or_dpath_args", "or_statfs_args", "or_maps_args"]
    names = ["or_reverse_visible", "or_uid_matches", "or_find_by_path", "or_find_by_inode",
             "susfs_open_redirect_match_path", "or_find_by_redirected_inode", "or_reverse_lookup",
             "or_spoof_ids_legacy", "susfs_open_redirect_spoof_ids", "or_is_redirected_path",
             "or_dpath_entry", "or_dpath_ret", "or_statfs_entry", "or_statfs_ret",
             "or_maps_entry", "or_buf_replace", "or_maps_ret", "or_fdinfo_find_dec",
             "or_fdinfo_write_dec", "or_fdinfo_ret", "or_register",
             "susfs_open_redirect_group_write_begin", "susfs_open_redirect_group_write_end",
             "susfs_open_redirect_active", "susfs_open_redirect_group_prepare_locked",
             "susfs_open_redirect_group_routes", "or_resolve_rule",
             "susfs_open_redirect_resolve_group", "or_legacy_write_check", "or_prepare_legacy",
             "or_commit_legacy_locked", "or_add", "or_release_slot", "or_reclaim_slot",
             "or_clear_all", "or_del", "split_ws", "or_proc_write"]
    pieces = {name: definition(source, name, True) for name in structs}
    pieces.update({name: definition(source, name) for name in names})
    entry_path = repo / "kernel/susfs_or_entry.c"
    pieces["or_lookup_flags"] = definition(entry_path.read_text(encoding="utf-8"), "or_lookup_flags")
    pieces["susfs_or_entry_routes"] = definition(entry_path.read_text(encoding="utf-8"), "susfs_or_entry_routes")
    pieces["susfs_opath_open_routes"] = definition((repo / "kernel/susfs_opath.c").read_text(encoding="utf-8"), "susfs_opath_open_routes")
    if args.mutation == "map-interval":
        pieces["or_buf_replace"] = pieces["or_buf_replace"].replace("for (i = start;", "for (i = 0;")
    elif args.mutation == "writer-recheck":
        pieces["or_commit_legacy_locked"] = pieces["or_commit_legacy_locked"].replace("if (skp_policy_paths_active())\n\t\treturn -EBUSY;", "/* mutation: missing ownership recheck */")
    elif args.mutation == "group-fallback":
        pieces["susfs_open_redirect_match_path"] = pieces["susfs_open_redirect_match_path"].replace("if (mode == SKP_OBJECT_GROUPED)", "if (mode == SKP_OBJECT_GROUPED && result.matched)")
    generated = evidence / "redirect-hook-regression-extracted.c"
    generated.write_text(PREAMBLE + "\n" + "\n".join(pieces[n] for n in structs) + GLOBALS +
                         "\n\n".join(pieces[n] for n in names) + "\n" + pieces["or_lookup_flags"] +
                         "\n" + pieces["susfs_opath_open_routes"] + "\n" + pieces["susfs_or_entry_routes"] + TESTS,
                         encoding="utf-8")
    receipt = {"production_source": "kernel/susfs_open_redirect.c", "kernel_calls": False, "mutation": args.mutation,
               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "additional_source_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                                            for name in ["kernel/susfs_or_entry.c", "kernel/susfs_opath.c"]},
               "extracted_sha256": {n: hashlib.sha256(p.encode()).hexdigest() for n, p in pieces.items()},
               "limits": "Typed host doubles; not whole-TU/kernel RCU/VFS/userfault/probe/device validation.",
               "runs": []}
    for label, flags in [("strict", ["-O2"]),
                         ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("redirect-hook-regression-" + label + ".bin")
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
            match = re.search(r"REDIRECT_HOOK_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "redirect-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
