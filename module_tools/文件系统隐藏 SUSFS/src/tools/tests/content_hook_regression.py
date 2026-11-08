#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the production content engine against typed host doubles.

Only kernel include directives are removed from the production translation unit.
Its declarations, initializers and function bodies are retained verbatim. This
checks ownership, failure paths and byte handling; it is not a kernel or device
test and cannot establish actual LSM, CFI, namespace or VFS behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from kstat_hook_regression import execute
from path_hook_regression import execution_path


PREAMBLE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef unsigned char u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned short umode_t;
typedef void *fl_owner_t;
#define __nocfi
#define noinline
#define static_assert _Static_assert
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#ifndef TEST_KERNEL_VERSION
#define TEST_KERNEL_VERSION KERNEL_VERSION(6,12,0)
#endif
#define LINUX_VERSION_CODE TEST_KERNEL_VERSION
#define GFP_KERNEL 0
#define PAGE_SIZE 4096UL
#define PAGE_ALIGN(n) (((n)+PAGE_SIZE-1)&~(PAGE_SIZE-1))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_rmb() atomic_thread_fence(memory_order_acquire)
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define SUSFS_LOGI(...) ((void)0)
#define PROC_SUPER_MAGIC 0x9fa0
#define EXT4_SUPER_MAGIC 0xef53
#define F2FS_SUPER_MAGIC 0xf2f52010
#define TMPFS_MAGIC 0x01021994
#define EROFS_SUPER_MAGIC_V1 0xe0f5e1e2
#define FUSE_SUPER_MAGIC 0x65735546
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#define FMODE_READ (1U<<0)
#define FMODE_WRITE (1U<<1)
#define FMODE_CAN_READ (1U<<2)
#define FMODE_CAN_WRITE (1U<<3)
#define FMODE_LSEEK (1U<<4)
#define FMODE_PREAD (1U<<5)
#define FMODE_PWRITE (1U<<6)
#define IOCB_DIRECT (1U<<0)
#define IOCB_NOWAIT (1U<<1)
#define IOCB_HIPRI (1U<<2)
#define IOCB_WRITE (1U<<3)
#define TEST_ENCRYPTED (1U<<0)
#define TEST_VERITY (1U<<1)
#define TEST_DAX (1U<<2)
#define IS_ENCRYPTED(i) (((i)->test_flags&TEST_ENCRYPTED)!=0)
#define IS_VERITY(i) (((i)->test_flags&TEST_VERITY)!=0)
#define IS_DAX(i) (((i)->test_flags&TEST_DAX)!=0)
#define SUSFS_OR_ENTRY_OPENAT 0
#define SUSFS_OR_ENTRY_OPENAT2 1

static atomic_uint checks;
static _Thread_local unsigned int held_locks;
static void expect(bool condition,const char *message)
{
 unsigned int number=atomic_fetch_add(&checks,1)+1;
 if(!condition) { fprintf(stderr,"FAIL check=%u %s\n",number,message);abort(); }
}
static unsigned int warned;
static bool test_warn(bool x) { if(x) warned++;return x; }
#define WARN_ON_ONCE(x) test_warn(x)

typedef struct { atomic_long value; } atomic_long_t;
#define ATOMIC_LONG_INIT(x) { ATOMIC_VAR_INIT(x) }
static long atomic_long_read(const atomic_long_t *a) { return atomic_load(&a->value); }
static long atomic_long_cmpxchg(atomic_long_t *a,long old,long next)
{ atomic_compare_exchange_strong(&a->value,&old,next);return old; }
static void atomic_long_sub(long n,atomic_long_t *a)
{ expect(atomic_fetch_sub(&a->value,n)>=n,"reservation cannot underflow"); }
typedef struct { atomic_uint value; } refcount_t;
static void refcount_set(refcount_t *r,unsigned int n) { atomic_init(&r->value,n); }
static void refcount_inc(refcount_t *r)
{ expect(atomic_fetch_add(&r->value,1)>0,"cannot acquire a dead payload"); }
static bool refcount_dec_and_test(refcount_t *r)
{ unsigned int old=atomic_fetch_sub(&r->value,1);expect(old>0,"payload reference cannot underflow");return old==1; }

struct spinlock { pthread_mutex_t mutex; };
#define DEFINE_SPINLOCK(n) struct spinlock n={PTHREAD_MUTEX_INITIALIZER}
#define spin_lock_irqsave(l,f) do { (f)=0;expect(!pthread_mutex_lock(&(l)->mutex),"take host lock");held_locks++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f);expect(held_locks>0,"release held lock");held_locks--;expect(!pthread_mutex_unlock(&(l)->mutex),"unlock host lock"); } while(0)
struct hlist_node { struct hlist_node *next;struct hlist_node **pprev; };
struct hlist_head { struct hlist_node *first; };
#define DEFINE_HASHTABLE(n,bits) struct hlist_head n[1U<<(bits)]
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define bucket(t,k) (((uintptr_t)(k)>>3)&(ARRAY_SIZE(t)-1))
static void test_hash_add(struct hlist_head *head,struct hlist_node *n)
{ n->next=head->first;n->pprev=&head->first;if(n->next)n->next->pprev=&n->next;head->first=n; }
#define hash_add(t,n,k) test_hash_add(&(t)[bucket(t,k)],(n))
static void hash_del(struct hlist_node *n)
{ expect(n->pprev!=NULL,"hash entry is linked exactly once");*n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;n->next=NULL;n->pprev=NULL; }
#define hash_for_each_possible(t,p,m,k) \
 for(struct hlist_node *_node=(t)[bucket(t,k)].first;_node&&((p)=container_of(_node,typeof(*(p)),m),true);_node=_node->next)
#define hash_empty(t) test_hash_empty(t,ARRAY_SIZE(t))
static bool test_hash_empty(struct hlist_head *t,size_t n)
{ for(size_t i=0;i<n;i++)if(t[i].first)return false;return true; }

static atomic_uint allocated_objects;
static unsigned int fail_kzalloc,fail_vzalloc;
static void *kzalloc(size_t n,int ignored)
{ (void)ignored;expect(!held_locks,"allocation outside spinlock");if(fail_kzalloc){fail_kzalloc--;return NULL;}void *p=calloc(1,n);if(p)atomic_fetch_add(&allocated_objects,1);return p; }
static void *vzalloc(size_t n)
{ expect(!held_locks,"vmalloc outside spinlock");if(fail_vzalloc){fail_vzalloc--;return NULL;}void *p=calloc(1,n);if(p)atomic_fetch_add(&allocated_objects,1);return p; }
static void test_free(void *p)
{ if(!p)return;expect(!held_locks,"free outside spinlock");expect(atomic_fetch_sub(&allocated_objects,1)>0,"tracked allocation exists");free(p); }
#define kfree test_free
#define vfree test_free

struct file;
struct inode;
struct iov_iter;
struct kiocb;
struct module { atomic_int refs;bool accepting; };
static struct module wrapper_module={ATOMIC_VAR_INIT(0),true};
static struct module original_module={ATOMIC_VAR_INIT(0),true};
static struct module target_module={ATOMIC_VAR_INIT(0),true};
#define THIS_MODULE (&wrapper_module)
struct file_operations {
 struct module *owner;
 ssize_t (*read_iter)(struct kiocb *,struct iov_iter *);
 loff_t (*llseek)(struct file *,loff_t,int);
 int (*release)(struct inode *,struct file *);
 int (*flush)(struct file *,fl_owner_t);
 ssize_t (*read)(struct file *,char *,size_t,loff_t *);
 ssize_t (*write)(struct file *,const char *,size_t,loff_t *);
 ssize_t (*write_iter)(struct kiocb *,struct iov_iter *);
 int (*mmap)(struct file *,void *);
 ssize_t (*splice_read)(struct file *,loff_t *,void *,size_t,unsigned int);
 ssize_t (*copy_file_range)(struct file *,loff_t,struct file *,loff_t,size_t,unsigned int);
 long (*unlocked_ioctl)(struct file *,unsigned int,unsigned long);
};
static bool try_module_get(struct module *m)
{ if(!m)return true;if(!m->accepting)return false;atomic_fetch_add(&m->refs,1);return true; }
static void module_put(struct module *m)
{ if(m)expect(atomic_fetch_sub(&m->refs,1)>0,"module pin release balances acquired reference"); }
static void fops_put(const struct file_operations *ops)
{ if(ops&&ops->owner)expect(atomic_fetch_sub(&ops->owner->refs,1)>0,"module owner reference balanced"); }
struct qstr { const char *name;size_t len; };
struct super_block { dev_t s_dev;unsigned long s_magic;struct dentry *s_root; };
struct inode { struct super_block *i_sb;unsigned long i_ino;u32 i_generation;umode_t i_mode;loff_t i_size;const struct file_operations *i_fop;unsigned int test_flags; };
struct dentry { struct inode *inode;struct dentry *d_parent;struct qstr d_name; };
struct vfsmount { unsigned int id; };
struct path { struct dentry *dentry;struct vfsmount *mnt; };
struct file {
 struct path f_path;
 const struct file_operations *f_op;
 unsigned int f_mode;
 unsigned long f_flags;
 loff_t f_pos;
 void *f_mapping,*f_cred,*f_security,*private_data;
 bool opened;
 unsigned int uid;
 atomic_uint refs;
};
struct filename { const char *name; };
struct open_how { u64 flags,mode,resolve; };
struct open_flags { unsigned long flags,mode,resolve; };
struct task_struct { unsigned int id; };
static struct task_struct task_a={1},task_b={2};
static _Thread_local struct task_struct *test_current=&task_a;
#define current test_current
static _Thread_local unsigned int current_uid_value;
static struct inode *d_inode(struct dentry *d) { return d->inode; }
static struct inode *file_inode(struct file *f) { return d_inode(f->f_path.dentry); }
static loff_t i_size_read(struct inode *i) { return i->i_size; }
struct test_vec { char *data;size_t size; };
struct iov_iter { struct test_vec vec[4];size_t nr,index,offset,count;long budget; };
struct kiocb { struct file *ki_filp;loff_t ki_pos;unsigned int ki_flags; };
static size_t iov_iter_count(const struct iov_iter *it) { return it->count; }

union security_list_options { int (*file_open)(struct file *); };
struct ksu_lsm_hook { int (*replacement)(struct file *);void *original;void *entry; };
#define KSU_LSM_HOOK_INSERT(member,fn) { .replacement=(fn) }
static int kern_path(const char *,unsigned int,struct path *);
static void path_put(struct path *);
static void fput(struct file *);
static void *find_kernel_symbol_exact(const char *);
static int ksu_register_lsm_hook(struct ksu_lsm_hook *);
static void ksu_unregister_lsm_hook(struct ksu_lsm_hook *);
static bool skp_policy_content_source_applies(const struct path *);
static bool name_hidden;
static bool sus_path_name_dentry_hidden(const struct dentry *dentry)
{ (void)dentry;return name_hidden; }
static unsigned int susfs_or_entry_routes(void);
static unsigned int susfs_kstat_group_routes(void);
static bool sus_path_group_watch_ready(void);
#define LOOKUP_FOLLOW 1U
'''


DOUBLES = r'''
static const struct file_operations source_ops,local_ext4_ops,local_f2fs_ops,local_tmpfs_ops,local_erofs_ops;
static struct dentry proc_root;
static struct dentry local_root;
static struct super_block proc_sb={17,PROC_SUPER_MAGIC,&proc_root};
static struct super_block target_sb={23,EXT4_SUPER_MAGIC,NULL};
static struct super_block local_sb={31,EXT4_SUPER_MAGIC,&local_root};
static struct inode source_inode={.i_sb=&proc_sb,.i_ino=101,.i_generation=11,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
static struct inode meminfo_inode={.i_sb=&proc_sb,.i_ino=102,.i_generation=12,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
static struct inode version_inode={.i_sb=&proc_sb,.i_ino=103,.i_generation=13,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
static struct inode target_inode={.i_sb=&target_sb,.i_ino=201,.i_generation=21,.i_mode=S_IFREG|0600};
static struct inode changed_inode={.i_sb=&proc_sb,.i_ino=104,.i_generation=14,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
static struct inode other_proc_inode={.i_sb=&proc_sb,.i_ino=199,.i_generation=19,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
static struct inode local_inode={.i_sb=&local_sb,.i_ino=301,.i_generation=31,.i_mode=S_IFREG|0644,.i_size=3,.i_fop=&local_ext4_ops};
static struct inode extra_inodes[5];
static struct dentry source_dentry={&source_inode,&proc_root,{"cpuinfo",7}};
static struct dentry meminfo_dentry={&meminfo_inode,&proc_root,{"meminfo",7}};
static struct dentry version_dentry={&version_inode,&proc_root,{"version",7}};
static struct dentry target_dentry={&target_inode,NULL,{"target",6}};
static struct dentry changed_dentry={&changed_inode,&proc_root,{"cpuinfo",7}};
static struct dentry other_proc_dentry={&other_proc_inode,&proc_root,{"other",5}};
static struct dentry local_dentry={&local_inode,&local_root,{"source",6}};
static struct dentry extra_dentries[5];
static struct vfsmount proc_mount={1},target_mount={2},other_mount={3};
static const struct path source_path={&source_dentry,&proc_mount};
static const struct path meminfo_path={&meminfo_dentry,&proc_mount};
static const struct path version_path={&version_dentry,&proc_mount};
static const struct path target_path={&target_dentry,&target_mount};
static const struct path changed_path={&changed_dentry,&proc_mount};
static const struct path local_path={&local_dentry,&target_mount};
static const char *extra_names[]={"uptime","loadavg","stat","cmdline","bootconfig"};
static const struct path *source_path_for_open=&source_path;
static unsigned char target_data[1024*1024+2];
static size_t target_length,read_chunk_limit;
static unsigned int live_paths,live_files,source_releases,target_releases;
static unsigned int lookup_calls,target_opens,source_opens,kernel_reads,copy_calls,lsm_calls;
static unsigned int last_source_uid,last_target_uid;
static int fail_lookup,fail_target_open,fail_source_open,fail_build,original_lsm_result;
static int read_fail_after=-1;
static unsigned int native_routes=(1U<<SUSFS_OR_ENTRY_OPENAT)|(1U<<SUSFS_OR_ENTRY_OPENAT2);
static unsigned int kstat_routes=7;
static bool path_watch_ready=true;
static struct file *fd_table[64];
static int hook_error;
static unsigned int hook_installs,hook_uninstalls;
static const char *missing_symbol;
static bool policy_active=true,source_dac_allowed=true,skip_lsm,change_after_lsm;
static bool target_identity_changed,post_read_size_changed;
static bool post_read_metadata_changed;
static bool change_open_fops;
static unsigned int change_open_flags;
static unsigned int flush_calls;
static int original_flush_result;
static fl_owner_t last_flush_owner;
static int credential_marker,security_marker,mapping_marker,source_private,target_private;
static int last_dfd;
static struct open_how last_how;
static struct filename *last_name;
static unsigned int original_content_calls;
static int original_source_release(struct inode *inode,struct file *file)
{
 expect(!held_locks,"original source release outside lock");
 expect(inode==file_inode(file),"release receives A inode");
 expect(file->private_data==&source_private,"original A private_data preserved through release");
 expect(file->f_cred==&credential_marker&&file->f_security==&security_marker&&file->f_mapping==&mapping_marker,"A credential/security/mapping retained");
 expect(atomic_load(&original_module.refs)>0,"original owner alive during release");
 file->private_data=NULL;source_releases++;return 0;
}
static int original_target_release(struct inode *inode,struct file *file)
{ (void)inode;expect(file->private_data==&target_private,"target private data retained");target_releases++;return 0; }
static int original_source_flush(struct file *file,fl_owner_t owner)
{
 expect(!held_locks,"original flush outside hash lock");
 expect(file->private_data==&source_private&&file->f_security==&security_marker,"flush preserves original A private state");
 expect(atomic_load(&original_module.refs)>0&&atomic_load(&wrapper_module.refs)>0,"original and wrapper modules live throughout flush");
 flush_calls++;last_flush_owner=owner;return original_flush_result;
}
static ssize_t forbidden_read(struct file *f,char *b,size_t n,loff_t *p)
{ (void)f;(void)b;(void)n;(void)p;original_content_calls++;expect(false,"never call original A read");return 0; }
static ssize_t forbidden_iter(struct kiocb *i,struct iov_iter *v)
{ (void)i;(void)v;original_content_calls++;expect(false,"never call original A read_iter");return 0; }
static int forbidden_mmap(struct file *f,void *v)
{ (void)f;(void)v;original_content_calls++;expect(false,"never call original A mmap");return 0; }
static long forbidden_ioctl(struct file *f,unsigned int c,unsigned long a)
{ (void)f;(void)c;(void)a;original_content_calls++;expect(false,"never call original A ioctl");return 0; }
static ssize_t forbidden_splice(struct file *f,loff_t *p,void *b,size_t n,unsigned int flags)
{ (void)f;(void)p;(void)b;(void)n;(void)flags;original_content_calls++;expect(false,"never call original A splice");return 0; }
static const struct file_operations source_ops={.owner=&original_module,.read=forbidden_read,.read_iter=forbidden_iter,.mmap=forbidden_mmap,.unlocked_ioctl=forbidden_ioctl,.splice_read=forbidden_splice,.release=original_source_release};
static const struct file_operations local_ext4_ops={.owner=&original_module,.read_iter=forbidden_iter,.release=original_source_release};
static const struct file_operations local_f2fs_ops={.owner=&original_module,.read_iter=forbidden_iter,.release=original_source_release,.flush=original_source_flush};
static const struct file_operations local_tmpfs_ops={.owner=&original_module,.read_iter=forbidden_iter};
static const struct file_operations local_erofs_ops={.owner=&original_module,.read_iter=forbidden_iter};
static const struct file_operations target_ops={.owner=&target_module,.release=original_target_release};

static struct file *new_file(struct path path,bool target)
{
 struct file *f=calloc(1,sizeof(*f));expect(f!=NULL,"host file allocation succeeds");
 atomic_init(&f->refs,1);
 f->f_path=path;live_paths++;live_files++;
 f->f_op=target?&target_ops:path.dentry->inode->i_fop;
 expect(try_module_get(f->f_op->owner),"kernel takes original file ops owner");
 f->f_mode=FMODE_READ|FMODE_CAN_READ|FMODE_LSEEK|FMODE_PREAD;
 f->f_mapping=&mapping_marker;f->f_cred=&credential_marker;f->f_security=&security_marker;
 f->private_data=target?(void *)&target_private:(void *)&source_private;
 f->uid=current_uid_value;return f;
}
static void path_put(struct path *p)
{ expect(!held_locks&&p->dentry&&live_paths>0,"owned path release outside lock");live_paths--;p->dentry=NULL;p->mnt=NULL; }
static void fput(struct file *file)
{
 expect(!held_locks&&live_files>0,"file put outside lock");
 unsigned int references=atomic_fetch_sub(&file->refs,1);expect(references>0,"file reference cannot underflow");if(references>1)return;
 const struct file_operations *before=file->f_op;
 if(file->opened&&before->release)before->release(file_inode(file),file);
 expect(file->f_op==before,"release leaves current fops alive for __fput owner access");
 if(before==&content_fops)expect(before->owner==THIS_MODULE&&atomic_load(&wrapper_module.refs)>0,"__fput can still access wrapper owner after release");
 fops_put(file->f_op);path_put(&file->f_path);live_files--;free(file);
}
static int kern_path(const char *name,unsigned int flags,struct path *out)
{
 expect(!held_locks&&flags==LOOKUP_FOLLOW,"path lookup outside lock with expected flags");
 lookup_calls++;if(fail_lookup&&(int)lookup_calls==fail_lookup)return -ENOENT;
 if(!strcmp(name,"/proc/cpuinfo"))*out=source_path;
 else if(!strcmp(name,"/proc/meminfo"))*out=meminfo_path;
 else if(!strcmp(name,"/proc/version"))*out=version_path;
 else if(!strcmp(name,"/local/source"))*out=local_path;
 else {
  bool found=false;
  for(size_t i=0;i<ARRAY_SIZE(extra_names);i++)if(!strncmp(name,"/proc/",6)&&!strcmp(name+6,extra_names[i])){*out=(struct path){&extra_dentries[i],&proc_mount};found=true;break;}
  if(!found)*out=!strncmp(name,"/proc/",6)?(struct path){&other_proc_dentry,&proc_mount}:target_path;
 }
 live_paths++;return 0;
}
static struct file *fake_filp_open(const char *name,int flags,umode_t mode)
{
 expect(!held_locks,"B opens outside spinlock");expect(name[0]=='/'&&mode==0,"B absolute noncreating open");
 expect((flags&(O_ACCMODE|O_NOFOLLOW|O_NONBLOCK))==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK),"B open read-only nofollow nonblock");
 target_opens++;last_target_uid=current_uid_value;if(fail_target_open)return ERR_PTR(fail_target_open);
 struct file *f=new_file(target_identity_changed?changed_path:target_path,true);f->opened=true;return f;
}
static ssize_t fake_kernel_read(struct file *file,void *buffer,size_t count,loff_t *pos)
{
 expect(!held_locks&&file->f_op==&target_ops,"snapshot reads B outside spinlock");
 kernel_reads++;if(read_fail_after>=0&&(int)kernel_reads>read_fail_after)return -EIO;
 expect(*pos>=0,"B offset nonnegative");
 size_t offset=(size_t)*pos,n=offset>=target_length?0:target_length-offset;
 if(n>count)n=count;if(read_chunk_limit&&n>read_chunk_limit)n=read_chunk_limit;
 if(n)memcpy(buffer,target_data+offset,n);*pos+=(loff_t)n;
 if(post_read_size_changed)target_inode.i_size--;
 /* Metadata change is intentionally not a host assertion until production
  * defines a concurrent-writer contract beyond size/EOF validation. */
 (void)post_read_metadata_changed;
 return (ssize_t)n;
}
static int fake_build_flags(const struct open_how *how,struct open_flags *op)
{
 expect(atomic_load(&wrapper_module.refs)>0,"module is pinned before invoking full-open helpers");
 expect(!held_locks,"normal open flag construction outside lock");last_how=*how;
 if(fail_build)return fail_build;if(how->mode)return -EINVAL;
 op->flags=how->flags;op->mode=how->mode;op->resolve=how->resolve;return 0;
}
static int fake_original_lsm(struct file *file)
{ expect(!held_locks,"original LSM outside guard lock");expect(file->uid==current_uid_value,"A open inherits caller credentials");lsm_calls++;return original_lsm_result; }
static bool skp_policy_content_source_applies(const struct path *path)
{ return policy_active&&content_source_path(path)!=0; }
static struct file *fake_do_filp_open(int dfd,struct filename *name,const struct open_flags *op)
{
 expect(atomic_load(&wrapper_module.refs)>0,"module remains pinned throughout potentially blocking A open");
 expect(!held_locks,"full A open outside spinlock");source_opens++;last_dfd=dfd;last_name=name;last_source_uid=current_uid_value;
 if(fail_source_open)return ERR_PTR(fail_source_open);
 if(!source_dac_allowed)return ERR_PTR(-EACCES);
 struct file *f=new_file(*source_path_for_open,false);f->f_flags=op->flags;
 int result=skip_lsm?0:content_file_open(f);
 if(result){fput(f);return ERR_PTR(result);}f->opened=true;
 if(change_after_lsm)f->f_path=changed_path;
 if(change_open_fops)f->f_op=&source_ops;
 if(change_open_flags)file_inode(f)->test_flags|=change_open_flags;
 return f;
}
static loff_t fake_fixed_size_llseek(struct file *file,loff_t offset,int whence,loff_t size)
{
 loff_t base;
 if(whence==SEEK_SET)base=0;else if(whence==SEEK_CUR)base=file->f_pos;else if(whence==SEEK_END)base=size;else return -EINVAL;
 if(offset>0&&base>LLONG_MAX-offset)return -EINVAL;
 if(offset<0&&base<LLONG_MIN-offset)return -EINVAL;
 loff_t position=base+offset;if(position<0||position>size)return -EINVAL;
 file->f_pos=position;return position;
}
static size_t fake_copy_to_iter(const void *data,size_t bytes,struct iov_iter *it)
{
 expect(!held_locks,"copy_to_iter outside spinlock");copy_calls++;
 size_t count=bytes;if(count>it->count)count=it->count;
 if(it->budget>=0&&count>(size_t)it->budget)count=(size_t)it->budget;
 size_t copied=0;
 while(copied<count){expect(it->index<it->nr,"iterator segment exists");size_t n=it->vec[it->index].size-it->offset;if(n>count-copied)n=count-copied;memcpy(it->vec[it->index].data+it->offset,(const char *)data+copied,n);copied+=n;it->offset+=n;if(it->offset==it->vec[it->index].size){it->index++;it->offset=0;}}
 it->count-=copied;if(it->budget>=0)it->budget-=(long)copied;return copied;
}
static struct file *fake_fget_raw(unsigned int fd)
{
 if(fd>=ARRAY_SIZE(fd_table)||!fd_table[fd])return NULL;
 struct file *file=fd_table[fd];expect(atomic_fetch_add(&file->refs,1)>0,"fget pins existing open file");return file;
}
static void *find_kernel_symbol_exact(const char *name)
{
 if(missing_symbol&&!strcmp(name,missing_symbol))return NULL;
 if(!strcmp(name,"build_open_flags"))return (void *)fake_build_flags;
 if(!strcmp(name,"do_filp_open"))return (void *)fake_do_filp_open;
 if(!strcmp(name,"filp_open"))return (void *)fake_filp_open;
 if(!strcmp(name,"kernel_read"))return (void *)fake_kernel_read;
 if(!strcmp(name,"fixed_size_llseek"))return (void *)fake_fixed_size_llseek;
 if(!strcmp(name,"_copy_to_iter"))return (void *)fake_copy_to_iter;
 if(!strcmp(name,"fget_raw"))return (void *)fake_fget_raw;
 if(!strcmp(name,"ext4_file_operations"))return (void *)&local_ext4_ops;
 if(!strcmp(name,"f2fs_file_operations"))return (void *)&local_f2fs_ops;
 if(!strcmp(name,"shmem_file_operations"))return (void *)&local_tmpfs_ops;
 if(!strcmp(name,"erofs_file_fops"))return (void *)&local_erofs_ops;
 expect(false,"no unexpected dynamic import");return NULL;
}
static int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{ hook_installs++;if(hook_error)return hook_error;hook->original=(void *)fake_original_lsm;hook->entry=hook;return 0; }
static void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{ hook->entry=NULL;hook_uninstalls++; }
static unsigned int susfs_or_entry_routes(void) { return native_routes; }
static unsigned int susfs_kstat_group_routes(void) { return kstat_routes; }
static bool sus_path_group_watch_ready(void) { return path_watch_ready; }
'''


TESTS = r'''
static void balanced(void)
{
 expect(!live_paths&&!live_files&&!atomic_load(&allocated_objects),"no path/file/heap objects left");
 expect(!atomic_load(&wrapper_module.refs)&&!atomic_load(&original_module.refs)&&!atomic_load(&target_module.refs),"all module references balanced");
 expect(!susfs_content_bytes()&&hash_empty(content_files)&&hash_empty(content_guards),"no payload reservation/context/guard left");
 expect(!held_locks&&!warned&&!original_content_calls,"no lock leak, invariant warning or original A content call");
 bool empty=true;for(size_t i=0;i<ARRAY_SIZE(fd_table);i++)if(fd_table[i])empty=false;expect(empty,"host FD table released");
}
static void reset(void)
{
 balanced();
 name_hidden=false;
 content_enabled=true;wrapper_module.accepting=original_module.accepting=target_module.accepting=true;
 current=&task_a;current_uid_value=0;target_length=8;memcpy(target_data,"payload!",8);target_inode.i_size=8;
 proc_sb.s_magic=PROC_SUPER_MAGIC;target_sb.s_magic=EXT4_SUPER_MAGIC;source_inode.i_mode=S_IFREG|0444;target_inode.i_mode=S_IFREG|0600;
 source_dentry.d_parent=&proc_root;source_dentry.d_name=(struct qstr){"cpuinfo",7};
 source_inode.i_ino=101;source_inode.i_generation=11;source_inode.i_sb=&proc_sb;source_inode.i_fop=&source_ops;source_inode.test_flags=0;
 source_path_for_open=&source_path;change_open_fops=false;change_open_flags=0;flush_calls=0;original_flush_result=0;last_flush_owner=NULL;
 local_sb.s_magic=EXT4_SUPER_MAGIC;local_inode.i_ino=301;local_inode.i_generation=31;local_inode.i_mode=S_IFREG|0644;local_inode.i_size=3;local_inode.i_fop=&local_ext4_ops;local_inode.test_flags=0;
 target_inode.test_flags=0;
 for(size_t i=0;i<ARRAY_SIZE(extra_names);i++){
  extra_inodes[i]=(struct inode){.i_sb=&proc_sb,.i_ino=110+i,.i_generation=40+(u32)i,.i_mode=S_IFREG|0444,.i_fop=&source_ops};
  extra_dentries[i]=(struct dentry){&extra_inodes[i],&proc_root,{extra_names[i],strlen(extra_names[i])}};
 }
 fail_lookup=fail_target_open=fail_source_open=fail_build=original_lsm_result=0;
 fail_kzalloc=fail_vzalloc=0;read_fail_after=-1;read_chunk_limit=0;
 source_opens=target_opens=lookup_calls=kernel_reads=copy_calls=lsm_calls=0;
 source_releases=target_releases=0;last_source_uid=last_target_uid=0;
 source_dac_allowed=policy_active=true;skip_lsm=change_after_lsm=target_identity_changed=post_read_size_changed=post_read_metadata_changed=false;
 content_open_hook.original=(void *)fake_original_lsm;
 content_build_open_flags_fn=fake_build_flags;content_do_filp_open_fn=fake_do_filp_open;
 content_filp_open_fn=fake_filp_open;content_kernel_read_fn=fake_kernel_read;
 content_fixed_size_llseek_fn=fake_fixed_size_llseek;content_copy_to_iter_fn=fake_copy_to_iter;
 content_fget_raw_fn=fake_fget_raw;kstat_routes=7;path_watch_ready=true;
 content_ext4_fops=&local_ext4_ops;content_f2fs_fops=&local_f2fs_ops;content_tmpfs_fops=&local_tmpfs_ops;content_erofs_fops=&local_erofs_ops;
}
static struct susfs_content *prepare_source(const char *source)
{
 unsigned int paths_before=live_paths,files_before=live_files;
 struct susfs_content *payload=NULL;
 expect(susfs_content_prepare(source,"/data/B",&payload)==0&&payload!=NULL,"prepare valid private B payload");
 expect(live_paths==paths_before&&live_files==files_before,"prepare releases B file and lookup paths");return payload;
}
static struct susfs_content *prepare(void) { return prepare_source("/proc/cpuinfo"); }
static struct file *open_payload_from(struct susfs_content *payload,const struct path *path)
{
 static struct filename name={"relative-cpuinfo"};
 source_path_for_open=path;
 struct file *file=susfs_content_open(49,&name,O_RDONLY,0,0,path,payload);
 expect(!IS_ERR(file),"open authorized A returns wrapped file");
 expect(last_dfd==49&&last_name==&name,"original dfd and filename passed into full A open");
 expect(file->f_op==&content_fops&&file->f_path.dentry==path->dentry&&file->f_path.mnt==path->mnt,"A path preserved and wrapper installed before caller sees file");
 expect(file->private_data==&source_private&&file->f_mapping==&mapping_marker&&file->f_security==&security_marker&&file->f_cred==&credential_marker,"A private_data/mapping/credentials/security unchanged");
 expect((file->f_mode&(FMODE_WRITE|FMODE_CAN_WRITE|FMODE_PWRITE))==0,"wrapper exposes no write modes");
 expect(!file->f_op->read&&!file->f_op->write&&!file->f_op->write_iter&&!file->f_op->mmap&&!file->f_op->splice_read&&!file->f_op->copy_file_range&&!file->f_op->unlocked_ioctl,"unsupported content methods cannot call original A callbacks");
 return file;
}
static struct file *open_payload(struct susfs_content *payload) { return open_payload_from(payload,&source_path); }
static struct iov_iter iterator(char *buffer,size_t n,long budget)
{ struct iov_iter it={.vec={{buffer,n}},.nr=1,.count=n,.budget=budget};return it; }
static void test_prepare(void)
{
 reset();struct susfs_content *p=prepare();
 expect(p->size==8&&!memcmp(p->data,"payload!",8),"payload bytes match B");
 expect(susfs_content_bytes()==p->allocation&&p->allocation==PAGE_ALIGN(sizeof(*p)+9),"page-rounded header+EOF-byte reservation accounted");
 expect(last_target_uid==0,"B read using manager caller credentials");
 expect(susfs_content_matches_source(p,&source_path),"snapshot records source identity");
 expect(!susfs_content_matches_source(p,&changed_path)&&!susfs_content_matches_source(p,&meminfo_path),"different source identity and source kind denied");
 source_inode.i_generation++;expect(!susfs_content_matches_source(p,&source_path),"generation change invalidates prepared source");source_inode.i_generation--;
 susfs_content_get(p);susfs_content_put(p);expect(susfs_content_bytes()>0,"nonfinal put keeps reservation");susfs_content_put(p);balanced();
 const char *sources[]={"/proc/cpuinfo","/proc/meminfo","/proc/version","/proc/uptime","/proc/loadavg","/proc/stat","/proc/cmdline","/proc/bootconfig"};
 for(unsigned int i=0;i<ARRAY_SIZE(sources);i++){reset();p=NULL;expect(!susfs_content_prepare(sources[i],"/data/B",&p)&&p->source_kind==i+1,"each declared source reviewed kind is accepted");susfs_content_put(p);}
 reset();target_length=0;target_inode.i_size=0;p=prepare();expect(!p->size,"empty B allowed");susfs_content_put(p);
 reset();target_length=CONTENT_MAX_BYTES;target_inode.i_size=(loff_t)target_length;memset(target_data,0xa5,target_length);read_chunk_limit=30001;p=prepare();expect(p->size==CONTENT_MAX_BYTES&&kernel_reads>30&&p->data[p->size-1]==0xa5,"exact limit and repeated short reads reach EOF");susfs_content_put(p);
 const unsigned long magics[]={EXT4_SUPER_MAGIC,F2FS_SUPER_MAGIC,TMPFS_MAGIC,EROFS_SUPER_MAGIC_V1,FUSE_SUPER_MAGIC};
 for(size_t i=0;i<ARRAY_SIZE(magics);i++){reset();target_sb.s_magic=magics[i];p=prepare();susfs_content_put(p);}
 balanced();
}
static void failed_prepare(int expected,const char *message)
{
 struct susfs_content *p=(void *)(uintptr_t)1;
 expect(susfs_content_prepare("/proc/cpuinfo","/data/B",&p)==expected&&p==NULL,message);balanced();
}
static void test_prepare_failures(void)
{
 reset();content_enabled=false;failed_prepare(-EOPNOTSUPP,"not-ready rejects before reading B");
 reset();expect(susfs_content_prepare("/proc/cpuinfo","/data/B",NULL)==-EINVAL,"missing output pointer rejected");balanced();
 reset();struct susfs_content *p=NULL;expect(susfs_content_prepare("/proc/other","/data/B",&p)==-EOPNOTSUPP&&!target_opens,"unreviewed source rejected before B open");
 expect(susfs_content_prepare("/proc/cpuinfo","relative",&p)==-EOPNOTSUPP,"relative B rejected");
 reset();fail_lookup=1;failed_prepare(-ENOENT,"source lookup failure cleans paths");
 reset();fail_lookup=2;failed_prepare(-ENOENT,"target lookup failure cleans source path");
 reset();source_inode.i_mode=S_IFDIR|0555;failed_prepare(-EOPNOTSUPP,"nonregular source rejected");
 reset();source_dentry.d_parent=&target_dentry;failed_prepare(-EOPNOTSUPP,"same basename below another directory rejected");
 reset();proc_sb.s_magic=EXT4_SUPER_MAGIC;failed_prepare(-EOPNOTSUPP,"ordinary-file imitation of proc source rejected");
 reset();target_inode.i_mode=S_IFIFO|0600;failed_prepare(-EOPNOTSUPP,"FIFO target rejected before blocking open");
 reset();target_sb.s_magic=PROC_SUPER_MAGIC;failed_prepare(-EOPNOTSUPP,"proc target rejected");
 reset();target_sb.s_magic=0xbad;failed_prepare(-EOPNOTSUPP,"unrecognized target filesystem rejected");
 reset();fail_target_open=-EACCES;failed_prepare(-EACCES,"B authorization error preserved");
 reset();target_identity_changed=true;failed_prepare(-ESTALE,"B inode change during lookup/open rejected");
 reset();target_inode.i_size=-1;failed_prepare(-EFBIG,"negative advertised size rejected");
 reset();target_inode.i_size=CONTENT_MAX_BYTES+1;failed_prepare(-EFBIG,"oversized advertised B rejected");
 reset();fail_vzalloc=1;failed_prepare(-ENOMEM,"allocation failure releases reservation and B references");
 reset();read_fail_after=0;failed_prepare(-EIO,"first read error releases snapshot and B");
 reset();read_chunk_limit=2;read_fail_after=1;failed_prepare(-EIO,"late read error releases partially copied snapshot");
 reset();target_length=9;target_data[8]='x';failed_prepare(-EAGAIN,"extra EOF-probe byte detects growing B");
 reset();target_length=7;failed_prepare(-EAGAIN,"early EOF detects truncation");
 reset();post_read_size_changed=true;failed_prepare(-EAGAIN,"changed final size rejects B");
 reset();struct susfs_content *held[32];size_t count=0;while(count<ARRAY_SIZE(held)){int rc=susfs_content_prepare("/proc/cpuinfo","/data/B",&p);if(rc==-ENOSPC)break;expect(rc==0,"repeated payload allocation either succeeds or reports bound");held[count++]=p;/* use larger charges after first */target_length=CONTENT_MAX_BYTES;target_inode.i_size=CONTENT_MAX_BYTES;memset(target_data,0x31,target_length);}
 expect(count>1&&count<ARRAY_SIZE(held)&&susfs_content_bytes()<=CONTENT_TOTAL_BYTES,"total memory budget includes all live payloads");
 while(count)susfs_content_put(held[--count]);balanced();
}
static void test_guard(void)
{
 reset();struct file *f=new_file(source_path,false);
 expect(content_file_open(f)==-EOPNOTSUPP&&lsm_calls==1,"unwrapped A open denied after original LSM");
 policy_active=false;expect(content_file_open(f)==0,"exempt/unmatched A retains ordinary open");policy_active=true;
 original_lsm_result=-EACCES;expect(content_file_open(f)==-EACCES,"original LSM denial has precedence");original_lsm_result=0;
 name_hidden=true;expect(content_file_open(f)==-ENOENT,"shared file-open hook denies a matching basename before unguarded content fallback");
 original_lsm_result=-EACCES;expect(content_file_open(f)==-EACCES,"name matching preserves original LSM denial precedence");
 name_hidden=false;original_lsm_result=0;
 struct content_open_guard outer={.task=&task_a,.expected=&source_path};hash_add(content_guards,&outer.node,(unsigned long)&task_a);
 current=&task_b;expect(!content_consume_guard(f)&&!outer.consumed,"guard never inherited by another task");current=&task_a;
 struct path other=source_path;other.mnt=&other_mount;struct content_open_guard inner={.task=&task_a,.expected=&other};hash_add(content_guards,&inner.node,(unsigned long)&task_a);
 expect(!content_consume_guard(f)&&!inner.consumed&&!outer.consumed,"innermost mismatching guard cannot fall through to outer");hash_del(&inner.node);
 expect(content_file_open(f)==0&&outer.consumed,"exact task/mount/dentry/identity guard permits A once");
 expect(content_file_open(f)==-EOPNOTSUPP,"consumed guard cannot authorize a second A open");hash_del(&outer.node);
 struct content_open_guard denied={.task=&task_a,.expected=&source_path};hash_add(content_guards,&denied.node,(unsigned long)&task_a);original_lsm_result=-EACCES;
 expect(content_file_open(f)==-EACCES&&denied.consumed,"guard never bypasses original SELinux denial");hash_del(&denied.node);
 fput(f);balanced();
}
static void test_open_failures(void)
{
 reset();struct susfs_content *p=prepare();struct filename name={"/proc/cpuinfo"};struct file *f;
 const unsigned long badflags[]={O_WRONLY,O_RDWR,O_CREAT,O_TRUNC,O_APPEND,O_DIRECT,O_PATH};
 for(size_t i=0;i<ARRAY_SIZE(badflags);i++){unsigned int before=source_opens;f=susfs_content_open(1,&name,badflags[i],0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-EOPNOTSUPP&&source_opens==before,"unsupported flags rejected before original A open");}
 fail_build=-EINVAL;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-EINVAL&&!atomic_load(&wrapper_module.refs),"full open flag error preserved and early pin released");fail_build=0;
 fail_kzalloc=1;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ENOMEM&&!atomic_load(&wrapper_module.refs),"context allocation failure releases early pin before A open");
 source_dac_allowed=false;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-EACCES&&hash_empty(content_guards)&&!atomic_load(&wrapper_module.refs),"A DAC denial preserved, guard removed and early pin released");source_dac_allowed=true;
 original_lsm_result=-EACCES;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-EACCES&&hash_empty(content_guards)&&!atomic_load(&wrapper_module.refs),"A LSM denial preserved, guard removed and early pin released");original_lsm_result=0;
 fail_source_open=-ENOENT;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ENOENT&&hash_empty(content_guards)&&!atomic_load(&wrapper_module.refs),"namei error preserved, guard removed and early pin released");fail_source_open=0;
 skip_lsm=true;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ESTALE&&hash_empty(content_guards)&&!atomic_load(&wrapper_module.refs),"missing required LSM consumption fails closed and releases pin");skip_lsm=false;
 change_after_lsm=true;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ESTALE&&!atomic_load(&wrapper_module.refs),"changed source after authorization fails closed and releases pin");change_after_lsm=false;
 unsigned int opens_before=source_opens;wrapper_module.accepting=false;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ENODEV&&!atomic_load(&wrapper_module.refs)&&source_opens==opens_before,"module shutdown refuses before attempting A open");wrapper_module.accepting=true;
 source_inode.i_generation++;unsigned int before=source_opens;f=susfs_content_open(1,&name,0,0,0,&source_path,p);expect(IS_ERR(f)&&PTR_ERR(f)==-ESTALE&&source_opens==before,"stale snapshot source rejected before open");source_inode.i_generation--;
 expect(!live_files&&!live_paths&&hash_empty(content_files)&&hash_empty(content_guards),"failed A opens retain only caller payload");susfs_content_put(p);balanced();
}
static void test_read_and_lifetime(void)
{
 reset();struct susfs_content *p=prepare();current_uid_value=10001;fail_target_open=-EACCES;
 unsigned int before_target=target_opens;struct file *f=open_payload(p);
 expect(last_source_uid==10001&&last_target_uid==0&&target_opens==before_target,"A opened as app; app never reopens inaccessible B");
 expect(atomic_load(&original_module.refs)==1&&atomic_load(&wrapper_module.refs)==1,"original and wrapper owners both held");
 unsigned long charged=susfs_content_bytes();susfs_content_put(p);expect(susfs_content_bytes()==charged,"open file retains payload after rule reference removed");
 char first[3]={0},second[16]={0};struct iov_iter it={.vec={{first,3},{second,13}},.nr=2,.count=16,.budget=-1};struct kiocb io={.ki_filp=f};
 expect(content_read_iter(&io,&it)==8&&io.ki_pos==8&&!memcmp(first,"pay",3)&&!memcmp(second,"load!",5)&&it.count==8,"read_iter copies B across iov segments and advances byte offset");
 expect(content_read_iter(&io,&it)==0,"read at EOF returns zero");
 io.ki_pos=0;it=iterator(second,8,3);expect(content_read_iter(&io,&it)==3&&io.ki_pos==3&&!memcmp(second,"pay",3),"partial user copy returns copied bytes");
 it=iterator(second,8,0);expect(content_read_iter(&io,&it)==-EFAULT&&io.ki_pos==3,"complete usercopy fault does not change offset");
 io.ki_pos=-1;expect(content_read_iter(&io,&it)==-EINVAL,"negative byte offset rejected");
 io.ki_pos=LLONG_MAX;it=iterator(second,sizeof(second),-1);expect(content_read_iter(&io,&it)==0&&io.ki_pos==LLONG_MAX,"large offset does not overflow at EOF");
 io.ki_pos=0;it=iterator(second,0,-1);expect(content_read_iter(&io,&it)==0,"empty request returns zero");
 const unsigned int bad_iocb[]={IOCB_DIRECT,IOCB_NOWAIT,IOCB_HIPRI,IOCB_WRITE};
 for(size_t i=0;i<ARRAY_SIZE(bad_iocb);i++){io.ki_flags=bad_iocb[i];it=iterator(second,8,-1);expect(content_read_iter(&io,&it)==-EOPNOTSUPP&&io.ki_pos==0,"unsupported IOCB operation rejected without data");}io.ki_flags=0;
 expect(content_llseek(f,0,SEEK_END)==8&&content_llseek(f,-3,SEEK_CUR)==5&&content_llseek(f,0,SEEK_SET)==0,"seek bases use B length and file offset");
 expect(content_llseek(f,-1,SEEK_SET)==-EINVAL&&content_llseek(f,9,SEEK_SET)==-EINVAL&&content_llseek(f,0,999)==-EINVAL,"invalid/beyond-bound/unknown seeks rejected");
 expect(content_llseek(f,LLONG_MAX,SEEK_END)==-EINVAL,"seek overflow rejected");
 struct file absent={0};io.ki_filp=&absent;it=iterator(second,8,-1);expect(content_read_iter(&io,&it)==-EIO&&content_llseek(&absent,0,SEEK_SET)==-EIO,"missing context fails closed, never falls back to A");
 expect(!original_content_calls,"read and seek never use A content methods");fput(f);expect(source_releases==1,"original source release called once");balanced();
}
static void test_updates(void)
{
 reset();struct susfs_content *old=prepare();struct file *old_file=open_payload(old);susfs_content_put(old);
 memcpy(target_data,"NEW-data",8);struct susfs_content *fresh=prepare();struct file *new_file=open_payload(fresh);susfs_content_put(fresh);
 char a[9]={0},b[9]={0};struct iov_iter ia=iterator(a,8,-1),ib=iterator(b,8,-1);struct kiocb oa={.ki_filp=old_file},ob={.ki_filp=new_file};
 expect(content_read_iter(&oa,&ia)==8&&content_read_iter(&ob,&ib)==8&&!memcmp(a,"payload!",8)&&!memcmp(b,"NEW-data",8),"old FD keeps old payload while new FD uses reapplied B");
 unsigned long before=susfs_content_bytes();fput(old_file);expect(susfs_content_bytes()<before&&susfs_content_bytes()>0,"last old FD releases only old memory charge");fput(new_file);balanced();
}
static void test_regular_sources(void)
{
 const unsigned long magics[]={EXT4_SUPER_MAGIC,F2FS_SUPER_MAGIC,TMPFS_MAGIC,EROFS_SUPER_MAGIC_V1};
 const struct file_operations *ops[]={&local_ext4_ops,&local_f2fs_ops,&local_tmpfs_ops,&local_erofs_ops};
 const unsigned int masks[]={SUSFS_CONTENT_FS_EXT4,SUSFS_CONTENT_FS_F2FS,SUSFS_CONTENT_FS_TMPFS,SUSFS_CONTENT_FS_EROFS};
 for(size_t i=0;i<ARRAY_SIZE(magics);i++){
  reset();local_sb.s_magic=magics[i];local_inode.i_fop=ops[i];
  expect((susfs_content_regular_filesystems()&masks[i])!=0,"available local filesystem advertised");
  expect(content_regular_ops(&local_inode)==ops[i],"local source requires exact audited inode fops");
  struct susfs_content *p=prepare_source("/local/source");
  expect(susfs_content_is_regular(p)&&p->source_kind==CONTENT_SOURCE_REGULAR&&susfs_content_size(p)==8,"ordinary source classified and exposes B size");
  current_uid_value=10001;unsigned int b_opens=target_opens;fail_target_open=-EACCES;
  struct file *f=open_payload_from(p,&local_path);susfs_content_put(p);
  expect(last_source_uid==10001&&target_opens==b_opens&&local_inode.i_size==3,"app opens real A with its credentials, leaves A inode size unchanged and never opens B");
  char output[16]={0};struct iov_iter it=iterator(output,sizeof(output),-1);struct kiocb io={.ki_filp=f};
  expect(content_read_iter(&io,&it)==8&&!memcmp(output,"payload!",8),"ordinary A shorter than B still returns all B bytes");
  expect(content_llseek(f,0,SEEK_END)==8,"ordinary seek end uses B payload length");
  fl_owner_t owner=&source_private;expect(f->f_op->flush&&f->f_op->flush(f,owner)==0,"wrapped close can flush source");
  if(i==1){expect(flush_calls==1&&last_flush_owner==owner,"F2FS flush receives original owner and state");original_flush_result=-EIO;expect(f->f_op->flush(f,owner)==-EIO&&flush_calls==2,"original flush error propagated without removing state");}
  else expect(!flush_calls,"absent original flush returns zero");
  expect(!source_releases&&atomic_load(&wrapper_module.refs)==1,"flush does not release the file or module reference");
  fput(f);expect(source_releases==(i<2?1U:0U),"original release called only when original table implements it");balanced();
 }
 const unsigned int disallowed_flags[]={TEST_ENCRYPTED,TEST_VERITY,TEST_DAX};
 for(size_t i=0;i<ARRAY_SIZE(disallowed_flags);i++){
  reset();local_inode.test_flags=disallowed_flags[i];struct susfs_content *p=NULL;
  expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p&&!target_opens,"encrypted verity and DAX sources refused before B read");balanced();
  reset();p=prepare_source("/local/source");local_inode.test_flags=disallowed_flags[i];source_path_for_open=&local_path;
  struct filename name={"/local/source"};struct file *f=susfs_content_open(2,&name,0,0,0,&local_path,p);
  expect(IS_ERR(f)&&PTR_ERR(f)==-ESTALE&&!source_opens,"source protection enabled after prepare rejects open");susfs_content_put(p);balanced();
  reset();p=prepare_source("/local/source");source_path_for_open=&local_path;change_open_flags=disallowed_flags[i];
  f=susfs_content_open(2,&name,0,0,0,&local_path,p);
  expect(IS_ERR(f)&&PTR_ERR(f)==-ESTALE&&!atomic_load(&wrapper_module.refs),"source protection enabled during actual open rejects wrapping and drops pin");susfs_content_put(p);balanced();
 }
 reset();local_inode.i_fop=&source_ops;struct susfs_content *p=NULL;
 expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p,"custom inode fops rejected despite ext4 magic");balanced();
 reset();p=prepare_source("/local/source");source_path_for_open=&local_path;change_open_fops=true;struct filename name={"/local/source"};
 struct file *f=susfs_content_open(3,&name,0,0,0,&local_path,p);
 expect(IS_ERR(f)&&PTR_ERR(f)==-EOPNOTSUPP&&!atomic_load(&wrapper_module.refs),"open callback interposing another fops table is rejected");susfs_content_put(p);balanced();
 const unsigned long excluded_magics[]={FUSE_SUPER_MAGIC,PROC_SUPER_MAGIC,0x62656572UL,0xbadUL};
 for(size_t i=0;i<ARRAY_SIZE(excluded_magics);i++){
  reset();local_sb.s_magic=excluded_magics[i];p=NULL;
  expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p&&!target_opens,"FUSE and unreviewed pseudo filesystems refused as generic A");balanced();
 }
 reset();local_inode.i_mode=S_IFDIR|0555;p=NULL;
 expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p,"directory cannot enter regular content mode");balanced();
 reset();local_inode.i_mode=S_IFCHR|0444;p=NULL;
 expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p,"read-only character device cannot enter ordinary file mode");balanced();
 reset();local_inode.i_mode=S_IFREG|0000;p=prepare_source("/local/source");source_path_for_open=&local_path;source_dac_allowed=false;
 f=susfs_content_open(3,&name,0,0,0,&local_path,p);
 expect(IS_ERR(f)&&PTR_ERR(f)==-EACCES&&!atomic_load(&wrapper_module.refs),"ordinary A DAC refusal survives even when B is readable");susfs_content_put(p);balanced();
 reset();p=prepare_source("/local/source");source_path_for_open=&local_path;original_lsm_result=-EACCES;
 f=susfs_content_open(3,&name,0,0,0,&local_path,p);
 expect(IS_ERR(f)&&PTR_ERR(f)==-EACCES&&!atomic_load(&wrapper_module.refs),"ordinary A SELinux refusal survives even when B is readable");susfs_content_put(p);balanced();
 reset();target_inode.test_flags=TEST_ENCRYPTED|TEST_VERITY|TEST_DAX;p=prepare_source("/local/source");
 expect(p!=NULL,"B is read normally by manager; source-only exclusions are not applied to B");susfs_content_put(p);balanced();
 reset();struct file absent={0};expect(content_flush(&absent,NULL)==-EIO,"flush with absent wrapper context fails closed");balanced();
}
static void test_regular_capabilities(void)
{
 reset();expect(susfs_content_regular_filesystems()==15,"all four resolved local filesystem capabilities advertised");
 content_enabled=false;expect(!susfs_content_regular_filesystems(),"disabled engine advertises no regular capability");content_enabled=true;
 {
  path_watch_ready=false;struct susfs_content *p=NULL;
  expect(!susfs_content_regular_filesystems()&&susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p,"missing inode lifetime watch disables regular capability and source admission");
  p=prepare();expect(p&&!susfs_content_is_regular(p),"proc content remains available without regular inode lifetime watch");susfs_content_put(p);path_watch_ready=true;balanced();
 }
 for(unsigned int bit=1;bit<=4;bit<<=1){kstat_routes=7U&~bit;struct susfs_content *p=NULL;expect(!susfs_content_regular_filesystems()&&susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP,"missing native stat route disables ordinary source admission");}
 kstat_routes=7;content_fget_raw_fn=NULL;struct susfs_content *p=NULL;
 expect(!susfs_content_regular_filesystems()&&susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP,"missing FD lookup disables ordinary sources");
 p=prepare();susfs_content_put(p);balanced();
 const char *names[]={"ext4_file_operations","f2fs_file_operations","shmem_file_operations","erofs_file_fops"};
 const unsigned int masks[]={SUSFS_CONTENT_FS_EXT4,SUSFS_CONTENT_FS_F2FS,SUSFS_CONTENT_FS_TMPFS,SUSFS_CONTENT_FS_EROFS};
 const unsigned long magics[]={EXT4_SUPER_MAGIC,F2FS_SUPER_MAGIC,TMPFS_MAGIC,EROFS_SUPER_MAGIC_V1};
 const struct file_operations *ops[]={&local_ext4_ops,&local_f2fs_ops,&local_tmpfs_ops,&local_erofs_ops};
 for(size_t i=0;i<ARRAY_SIZE(names);i++){
  reset();content_enabled=false;missing_symbol=names[i];expect(!susfs_content_init()&&susfs_content_ready(),"missing optional filesystem table keeps proc mode available");
  expect(susfs_content_regular_filesystems()==(15U&~masks[i]),"missing optional table disables only its filesystem");
  local_sb.s_magic=magics[i];local_inode.i_fop=ops[i];p=NULL;
  expect(susfs_content_prepare("/local/source","/data/B",&p)==-EOPNOTSUPP&&!p,"unavailable filesystem cannot register ordinary source");
  missing_symbol=NULL;susfs_content_exit();balanced();
 }
 reset();content_enabled=false;missing_symbol="fget_raw";expect(!susfs_content_init()&&susfs_content_ready()&&!susfs_content_regular_filesystems(),"missing optional fget keeps proc support with regular mode unavailable");missing_symbol=NULL;susfs_content_exit();balanced();
}
static void test_fd_sizes(void)
{
 reset();local_inode.i_size=99;target_length=4;target_inode.i_size=4;memcpy(target_data,"OLD!",4);
 struct susfs_content *p=prepare_source("/local/source");struct file *old=open_payload_from(p,&local_path);susfs_content_put(p);fd_table[7]=old;
 const char replacement[]="longer replacement";target_length=sizeof(replacement)-1;target_inode.i_size=(loff_t)target_length;memcpy(target_data,replacement,target_length);
 p=prepare_source("/local/source");struct file *fresh=open_payload_from(p,&local_path);susfs_content_put(p);fd_table[8]=fresh;
 unsigned long size=888;
 expect(susfs_content_fd_size(7,local_inode.i_ino,local_sb.s_dev,&size)&&size==4,"old bound FD reports its retained B size");
 expect(susfs_content_fd_size(8,local_inode.i_ino,local_sb.s_dev,&size)&&size==target_length,"new bound FD reports reapplied B size");
 expect(local_inode.i_size==99&&atomic_load(&old->refs)==1&&atomic_load(&fresh->refs)==1,"size lookup leaves source inode and FD references unchanged");
 size=888;expect(!susfs_content_fd_size(7,local_inode.i_ino+1,local_sb.s_dev,&size)&&size==888,"wrong inode key cannot rewrite reported size");
 expect(!susfs_content_fd_size(7,local_inode.i_ino,local_sb.s_dev+1,&size)&&size==888,"wrong device key cannot rewrite reported size");
 expect(!susfs_content_fd_size(63,local_inode.i_ino,local_sb.s_dev,&size)&&size==888,"empty FD cannot rewrite reported size");
 expect(!susfs_content_fd_size(99,local_inode.i_ino,local_sb.s_dev,&size)&&size==888,"invalid FD cannot rewrite reported size");
 expect(!susfs_content_fd_size(7,local_inode.i_ino,local_sb.s_dev,NULL),"null size output safely rejected");
 struct file *unwrapped=new_file(local_path,false);unwrapped->opened=true;fd_table[9]=unwrapped;
 expect(!susfs_content_fd_size(9,local_inode.i_ino,local_sb.s_dev,&size)&&size==888&&atomic_load(&unwrapped->refs)==1,"preexisting unwrapped A FD keeps true A size");
 p=prepare();struct file *proc=open_payload(p);susfs_content_put(p);fd_table[10]=proc;
 expect(!susfs_content_fd_size(10,source_inode.i_ino,proc_sb.s_dev,&size)&&size==888,"proc FD does not receive ordinary-file size view");
 expect(!susfs_content_is_regular(NULL)&&!susfs_content_size(NULL),"null metadata getters are safe");
 content_fget_raw_fn=NULL;expect(!susfs_content_fd_size(7,local_inode.i_ino,local_sb.s_dev,&size)&&size==888,"unavailable FD getter cannot mutate result");content_fget_raw_fn=fake_fget_raw;
 fd_table[7]=fd_table[8]=fd_table[9]=fd_table[10]=NULL;fput(old);fput(fresh);fput(unwrapped);fput(proc);balanced();
}
static pthread_barrier_t reserve_barrier;
static atomic_uint reservations_won;
static void *reserve_worker(void *ignored)
{
 (void)ignored;const size_t bytes=CONTENT_TOTAL_BYTES/8;
 bool acquired=content_reserve(bytes);if(acquired)atomic_fetch_add(&reservations_won,1);
 expect(atomic_long_read(&content_allocated)<=CONTENT_TOTAL_BYTES,"concurrent reservation never exceeds total cap");
 int result=pthread_barrier_wait(&reserve_barrier);expect(result==0||result==PTHREAD_BARRIER_SERIAL_THREAD,"reservation barrier reached");
 if(acquired)atomic_long_sub(bytes,&content_allocated);return NULL;
}
static void test_concurrent_reservation(void)
{
 reset();pthread_t threads[16];atomic_store(&reservations_won,0);expect(!pthread_barrier_init(&reserve_barrier,NULL,16),"initialize concurrent reservation barrier");
 for(size_t i=0;i<ARRAY_SIZE(threads);i++)expect(!pthread_create(&threads[i],NULL,reserve_worker,NULL),"start reservation worker");
 for(size_t i=0;i<ARRAY_SIZE(threads);i++)expect(!pthread_join(threads[i],NULL),"join reservation worker");
 expect(atomic_load(&reservations_won)==8,"exactly cap-fitting concurrent requests acquire reservations");expect(!pthread_barrier_destroy(&reserve_barrier),"destroy reservation barrier");balanced();
}
static void test_init(void)
{
 reset();content_enabled=false;native_routes=0;expect(susfs_content_init()==-EOPNOTSUPP&&!susfs_content_ready(),"missing native entry routes disables mode");
 native_routes=1U<<SUSFS_OR_ENTRY_OPENAT;expect(susfs_content_init()==-EOPNOTSUPP&&!susfs_content_ready(),"partial native entry routes disables mode");
 native_routes=(1U<<SUSFS_OR_ENTRY_OPENAT)|(1U<<SUSFS_OR_ENTRY_OPENAT2);
 const char *symbols[]={"build_open_flags","do_filp_open","filp_open","kernel_read","fixed_size_llseek","_copy_to_iter"};
 for(size_t i=0;i<ARRAY_SIZE(symbols);i++){missing_symbol=symbols[i];expect(susfs_content_init()==-ENOENT&&!susfs_content_ready(),"each missing required symbol disables content mode");}missing_symbol=NULL;
 hook_error=-EINVAL;expect(susfs_content_init()==-EINVAL&&!susfs_content_ready(),"LSM hook failure prevents readiness");hook_error=0;
 expect(!susfs_content_init()&&susfs_content_ready(),"complete imports and hook enable mode");unsigned int before=hook_uninstalls;susfs_content_exit();expect(!susfs_content_ready()&&hook_uninstalls==before+1,"shutdown disables mode and removes hook");susfs_content_exit();expect(hook_uninstalls==before+1,"disabled shutdown does not unhook twice");balanced();
}
int main(void)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(6,6,0)
 reset();content_enabled=false;content_open_hook.entry=NULL;policy_active=false;native_routes=0;
 missing_symbol="build_open_flags";hook_error=-EINVAL;
 expect(susfs_content_init()==-EINVAL&&!susfs_content_file_open_ready(),"6.6 failed shared hook stays unavailable");
 hook_error=0;
 expect(!susfs_content_init()&&susfs_content_file_open_ready(),"6.6 names-only hook installs without snapshot imports or native redirect routes");
 expect(!susfs_content_ready()&&!susfs_content_regular_filesystems(),"6.6 content capability remains disabled");
 expect(!strcmp(susfs_content_disabled_reason(),"kernel_6_6_disabled"),"6.6 reports intentional disable reason");
 struct susfs_content *payload=NULL;
 expect(susfs_content_prepare("/proc/cpuinfo","/data/B",&payload)==-EOPNOTSUPP&&!payload,"6.6 kernel rejects snapshot rules");
 struct file file={.f_path=source_path};
 expect(!content_file_open(&file)&&!lsm_calls,"6.6 pass continues the original LSM chain without calling a 6.12 slot");
 name_hidden=true;expect(content_file_open(&file)==-ENOENT,"6.6 shared hook enforces name hiding");
 unsigned int before=hook_uninstalls;susfs_content_exit();
 expect(!susfs_content_file_open_ready()&&hook_uninstalls==before+1,"6.6 names-only hook is removed despite disabled snapshots");
 susfs_content_exit();expect(hook_uninstalls==before+1,"6.6 repeated cleanup does not remove twice");balanced();
#else
 test_prepare();test_prepare_failures();test_guard();test_open_failures();
 test_read_and_lifetime();test_updates();test_regular_sources();test_regular_capabilities();test_fd_sizes();test_concurrent_reservation();test_init();
#endif
 printf("CONTENT_HOOK_REGRESSION checks=%u passed=true kernel_calls=false extracted_production=true\n",atomic_load(&checks));return 0;
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--kernel-version", choices=["6.6", "6.12"], default="6.12")
    parser.add_argument("--mutation", default="none", choices=[
        "none", "lsm-denial", "module-pin", "private-data", "source-generation",
        "regular-flags", "regular-fops", "flush", "fd-size-identity"],
        help="Deliberately alter one host-only production copy to check test sensitivity")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source_path = repo / "kernel/susfs_content.c"
    source = source_path.read_text(encoding="utf-8")
    header_path = repo / "kernel/susfs_content.h"
    header = header_path.read_text(encoding="utf-8")
    capability_defines = "\n".join(re.findall(r'^#define SUSFS_CONTENT_FS_[^\n]+', header, flags=re.M))
    # Preserve every production function body and global initializer. Header
    # contracts are supplied by typed host doubles rather than kernel headers.
    extracted, removed = re.subn(r'^#include[^\n]*\n', '', source, flags=re.M)
    if not removed or "susfs_content_matches_source" not in extracted:
        raise ValueError("production content engine or include boundaries missing")
    mutations = {
        "lsm-denial": ("int rc = content_original_file_open(file);",
                       "int rc = content_original_file_open(file); rc = 0;"),
        "module-pin": ("if (!try_module_get(THIS_MODULE))", "if (false)"),
        "private-data": ("file->f_op = &content_fops;",
                         "file->f_op = &content_fops; file->private_data = entry;"),
        "source-generation": ("inode->i_generation == content->source_generation;",
                              "true;"),
        "regular-flags": ("IS_ENCRYPTED(inode) ||\n\t    IS_VERITY(inode) || IS_DAX(inode)",
                          "false"),
        "regular-fops": ("return ops && inode->i_fop == ops ? ops : NULL;", "return ops;"),
        "flush": ("return ops->flush ? ops->flush(file, owner) : 0;", "return 0;"),
        "fd-size-identity": ("if (!inode || (u64)inode->i_ino != ino || (u64)inode->i_sb->s_dev != dev)",
                             "if (!inode)"),
    }
    if args.mutation != "none":
        old, new = mutations[args.mutation]
        if extracted.count(old) != 1:
            raise ValueError("mutation must match one production site")
        extracted = extracted.replace(old, new)
    generated = evidence / "content-hook-regression-extracted.c"
    generated.write_text(PREAMBLE + "\n" + capability_defines + "\n" + extracted + "\n" + DOUBLES + "\n" + TESTS,
                         encoding="utf-8")
    receipt = {
        "production_source": "kernel/susfs_content.c",
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "header_sha256": hashlib.sha256(header_path.read_bytes()).hexdigest(),
        "extracted_sha256": hashlib.sha256(extracted.encode()).hexdigest(),
        "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "mutation": args.mutation,
        "removed_include_directives": removed,
        "kernel_calls": False,
        "kernel_version": args.kernel_version,
        "limits": "Production bodies with typed host doubles; no actual VFS/LSM/CFI/RCU, kernel scheduler, namespace or device verification. Concurrent-writer contents beyond size/EOF checks are not guaranteed.",
        "runs": [],
    }
    for label, flags in [("strict", ["-O2"]),
                         ("asan-ubsan", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        binary = evidence / ("content-hook-regression-" + label + ".bin")
        command = [args.cc, "-std=gnu11", "-pthread", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-misleading-indentation", "-Wno-sign-compare",
                   "-DTEST_KERNEL_VERSION=" + ("0x060600" if args.kernel_version == "6.6" else "0x060c00"), *flags,
                   execution_path(generated), "-o", execution_path(binary)]
        build = execute(command)
        (evidence / (label + ".build.stdout.txt")).write_text(build.stdout, encoding="utf-8")
        (evidence / (label + ".build.stderr.txt")).write_text(build.stderr, encoding="utf-8")
        record = {"name": label, "build_exit": build.returncode, "passed": False}
        if not build.returncode:
            run = execute(["env", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1",
                           "UBSAN_OPTIONS=halt_on_error=1", execution_path(binary)])
            (evidence / (label + ".stdout.txt")).write_text(run.stdout, encoding="utf-8")
            (evidence / (label + ".stderr.txt")).write_text(run.stderr, encoding="utf-8")
            match = re.search(r"CONTENT_HOOK_REGRESSION checks=(\d+) passed=true kernel_calls=false extracted_production=true", run.stdout)
            record.update(run_exit=run.returncode, checks=int(match.group(1)) if match else 0,
                          passed=run.returncode == 0 and match is not None and not run.stderr)
        receipt["runs"].append(record)
    receipt["passed"] = all(run["passed"] for run in receipt["runs"])
    output = evidence / "content-hook-regression-receipt.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output), "runs": receipt["runs"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
