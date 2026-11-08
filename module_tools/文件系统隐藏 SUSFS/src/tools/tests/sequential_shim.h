/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SKP_SEQUENTIAL_SHIM_H
#define SKP_SEQUENTIAL_SHIM_H
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
typedef uint32_t u32;
typedef uint64_t u64;
static int susfs_dirent_status_json(char *buffer, size_t capacity) {
 return snprintf(buffer, capacity, "{\"native\":false,\"compat\":false,\"qualification_error\":-95}");
}
#define GFP_KERNEL 0
#define __user
#define HZ 100
#define THIS_MODULE NULL
#define READ_ONCE(p) __atomic_load_n(&(p), __ATOMIC_RELAXED)
#define WRITE_ONCE(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELAXED)
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define LOOKUP_FOLLOW 1
#define DEFINE_MUTEX(name) pthread_mutex_t name = PTHREAD_MUTEX_INITIALIZER
#define mutex_lock pthread_mutex_lock
#define mutex_unlock pthread_mutex_unlock
#define mutex_trylock(p) (!pthread_mutex_trylock(p))
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
#define entry(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define INIT_LIST_HEAD(p) do { (p)->next=(p); (p)->prev=(p); } while(0)
#define list_for_each_entry(pos, head, member) \
 for ((pos) = entry((head)->next, __typeof__(*(pos)), member); &(pos)->member != (head); \
      (pos) = entry((pos)->member.next, __typeof__(*(pos)), member))
#define list_for_each_entry_rcu list_for_each_entry
#define list_for_each_entry_safe(pos, tmp, head, member) \
 for ((pos) = entry((head)->next, __typeof__(*(pos)), member), \
      (tmp) = entry((pos)->member.next, __typeof__(*(pos)), member); &(pos)->member != (head); \
      (pos) = (tmp), (tmp) = entry((tmp)->member.next, __typeof__(*(tmp)), member))
static pthread_rwlock_t host_rcu = PTHREAD_RWLOCK_INITIALIZER;
static _Thread_local unsigned int host_rcu_depth;
static void rcu_read_lock(void) { if (!host_rcu_depth++) pthread_rwlock_rdlock(&host_rcu); }
static void rcu_read_unlock(void) { assert(host_rcu_depth); if (!--host_rcu_depth) pthread_rwlock_unlock(&host_rcu); }
static void synchronize_rcu(void) { assert(!host_rcu_depth); pthread_rwlock_wrlock(&host_rcu); pthread_rwlock_unlock(&host_rcu); }
static void list_add_tail(struct list_head *p, struct list_head *head) {
 p->prev = head->prev; p->next = head; head->prev->next = p; head->prev = p;
}
static void list_del(struct list_head *p) { p->prev->next = p->next; p->next->prev = p->prev; }
static void list_add_tail_rcu(struct list_head *p, struct list_head *head) {
 pthread_rwlock_wrlock(&host_rcu); list_add_tail(p, head); pthread_rwlock_unlock(&host_rcu);
}
static void list_del_rcu(struct list_head *p) {
 pthread_rwlock_wrlock(&host_rcu); list_del(p); pthread_rwlock_unlock(&host_rcu);
}
static void list_replace_rcu(struct list_head *old, struct list_head *replacement) {
 pthread_rwlock_wrlock(&host_rcu); replacement->next=old->next; replacement->prev=old->prev;
 replacement->next->prev=replacement; replacement->prev->next=replacement; pthread_rwlock_unlock(&host_rcu);
}
struct super_block { u64 s_dev; };
struct inode { struct super_block *i_sb; u64 i_ino; atomic_int refs, wrappers; u32 i_generation; unsigned int i_mode; };
struct dentry { struct dentry *d_parent; struct inode *inode; struct { char *name; } d_name; int d_lock; };
struct path { struct dentry *dentry; };
struct kstatfs { unsigned long f_type; };
struct cred { atomic_int refs; };
struct task_struct { struct task_struct *group_leader; atomic_int refs; };
static struct cred credentials;
static struct task_struct owner, app, child;
static _Thread_local struct task_struct *current;
static _Thread_local u32 host_uid;
static _Thread_local u32 host_accounting_uid;
struct uid_value { u32 val; };
static struct uid_value current_uid(void) { return (struct uid_value){host_uid}; }
static _Thread_local struct { struct uid_value uid; } host_user;
static int init_user_ns;
#define current_user_ns() (&init_user_ns)
#define current_user() (host_user.uid.val=host_accounting_uid, &host_user)
static void get_task_struct(struct task_struct *p) { p->refs++; }
static void put_task_struct(struct task_struct *p) { assert(p->refs-- > 0); }
static const struct cred *get_current_cred(void) { credentials.refs++; return &credentials; }
static void put_cred(const struct cred *p) { assert(atomic_fetch_sub(&((struct cred *)p)->refs,1) > 0); }
static const struct cred *override_creds(const struct cred *p) { return p; }
static void revert_creds(const struct cred *p) { (void)p; }
static atomic_int allocations;
static void *alloc(size_t n, bool zero) { void *p=zero?calloc(1,n):malloc(n); if(p) allocations++; return p; }
#define kzalloc(n, f) alloc((n),true)
#define kvzalloc(n, f) alloc((n),true)
#define kvmalloc(n, f) alloc((n),false)
static void kfree(const void *p) { if(p) { allocations--; free((void *)p); } }
#define kvfree kfree
static void *memdup_user(const void *p, size_t n) { void *q=alloc(n,false); if(!q)return(void *)-ENOMEM; memcpy(q,p,n);return q; }
static long strscpy(char *out, const char *in, size_t n) { size_t count=strlen(in); if(count>=n)return-E2BIG; memcpy(out,in,count+1);return count; }
#define spin_lock(p) ((void)(p))
#define spin_unlock(p) ((void)(p))
static struct super_block fixture_sb = { 10 };
static struct inode fixture_inode = { .i_sb=&fixture_sb, .i_ino=100 };
static struct dentry fixture_dentry = { .inode=&fixture_inode, .d_name={"fixture"} };
static bool missing_created;
static struct inode *d_inode(const struct dentry *d) { return d->inode; }
static struct inode *igrab(struct inode *i) { i->refs++;return i; }
static void iput(struct inode *i) { assert(i->refs-- > 0); }
static int kern_path(const char *p, int flags, struct path *out) {
 (void)flags; if(!strcmp(p,"/missing")&&!missing_created)return-ENOENT;
 if(!strcmp(p,"/bad"))return-EACCES;
 out->dentry=&fixture_dentry;return 0;
}
static void path_put(struct path *p) { p->dentry=NULL; }
static bool path_group_supported = true;
static bool sus_path_group_supported(void) { return path_group_supported; }
static bool sus_path_name_supported(void) { return true; }
static bool path_contents_supported = true;
static bool sus_path_contents_supported(void) { return path_contents_supported; }
static const char *sus_path_contents_disabled_reason(void) { return path_contents_supported ? "" : "directory_listing_unavailable"; }
static bool directory_names_ready = true;
static int susfs_directory_names_init(void) { return 0; }
static bool susfs_directory_names_ready(void) { return directory_names_ready; }
static void sus_path_group_write_begin(void) {}
static void sus_path_group_write_end(void) {}
static int sus_path_group_watch_inode(struct inode *i) { (void)i;return 0; }
static int sus_path_group_arm_readlink_locked(struct inode *i) { i->wrappers++;return 0; }
static void sus_path_group_disarm_readlink_locked(struct inode *i) { assert(i->wrappers-- > 0); }
#define susfs_kstat_group_write_begin sus_path_group_write_begin
#define susfs_kstat_group_write_end sus_path_group_write_end
#define susfs_map_group_write_begin sus_path_group_write_begin
#define susfs_map_group_write_end sus_path_group_write_end
#define susfs_mount_group_write_begin sus_path_group_write_begin
#define susfs_mount_group_write_end sus_path_group_write_end
#define susfs_open_redirect_group_write_begin sus_path_group_write_begin
#define susfs_open_redirect_group_write_end sus_path_group_write_end
static int susfs_kstat_group_prepare_locked(void) { return 0; }
static int susfs_map_group_prepare_locked(void) { return 0; }
static int susfs_mount_group_prepare_locked(void) { return 0; }
static int susfs_open_redirect_group_prepare_locked(bool forward) { (void)forward;return 0; }
struct skp_group_redirect_object;
static int susfs_open_redirect_resolve_group(const char *, const char *, struct skp_group_redirect_object *, struct kstatfs *, void *, void *);
struct skp_mount_query_result;
static bool susfs_mount_sequential_query(u64, u64, u64, struct skp_mount_query_result *);
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; };
#define DECLARE_DELAYED_WORK(name, callback) struct delayed_work name
static bool schedule_delayed_work(struct delayed_work *work, unsigned long delay) { (void)work;(void)delay;return true; }
static bool cancel_delayed_work_sync(struct delayed_work *work) { (void)work;return true; }
struct file { void *private_data; };
struct seq_file { void *private; char text[2048]; };
struct proc_dir_entry { int unused; };
struct proc_ops { int(*proc_open)(struct inode *,struct file *);ssize_t(*proc_read)(struct file *,char *,size_t,loff_t *);ssize_t(*proc_write)(struct file *,const char *,size_t,loff_t *);loff_t(*proc_lseek)(struct file *,loff_t,int);int(*proc_release)(struct inode *,struct file *); };
static int single_open(struct file *f,int(*show)(struct seq_file *,void *),void *p) { (void)show;struct seq_file *s=alloc(sizeof(*s),true);s->private=p;f->private_data=s;return 0; }
static int single_release(struct inode *i,struct file *f) { (void)i;kfree(f->private_data);f->private_data=NULL;return 0; }
static ssize_t seq_read(struct file *f,char *p,size_t n,loff_t *o) { (void)f;(void)p;(void)n;(void)o;return 0; }
static loff_t seq_lseek(struct file *f,loff_t o,int w) { (void)f;(void)w;return o; }
static void seq_printf(struct seq_file *s,const char *f,...) { va_list a;va_start(a,f);vsnprintf(s->text,sizeof(s->text),f,a);va_end(a); }
static bool susfs_control_node_allowed(void) { return true; }
static struct proc_dir_entry proc;
static struct proc_dir_entry *proc_create(const char *n,int m,void *p,const struct proc_ops *o) { (void)n;(void)m;(void)p;(void)o;return&proc; }
static void proc_remove(struct proc_dir_entry *p) { (void)p; }
#endif
