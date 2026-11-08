/* SPDX-License-Identifier: GPL-2.0-only */
#define SKP_SEQUENTIAL_HOSTTEST
#include "../../kernel/skp_policy_adapter.c"
struct susfs_content { atomic_int refs; unsigned int version, source_generation; bool regular; unsigned long size; };
static bool content_supported = true;
static int content_prepare_error;
static bool content_change_source;
static unsigned int content_prepares, content_live;
bool susfs_content_ready(void) { return content_supported; }
const char *susfs_content_disabled_reason(void) { return ""; }
unsigned long susfs_content_bytes(void) { return content_live * sizeof(struct susfs_content); }
unsigned int susfs_content_regular_filesystems(void) { return content_supported ? 15U : 0U; }
unsigned long susfs_content_size(const struct susfs_content *content) { return content->size; }
bool susfs_content_is_regular(const struct susfs_content *content) { return content->regular; }
void susfs_content_get(struct susfs_content *content) { assert(content->refs > 0); content->refs++; }
bool susfs_content_matches_source(const struct susfs_content *content,const struct path *path) {
 return path->dentry==&fixture_dentry&&content->source_generation==fixture_inode.i_generation;
}
void susfs_content_put(struct susfs_content *content) {
 assert(content->refs > 0);
 if (atomic_fetch_sub(&content->refs,1) == 1) { content_live--; kfree(content); }
}
int susfs_content_prepare(const char *source,const char *target,struct susfs_content **out) {
 assert(!pthread_mutex_trylock(&policy_write_lock));pthread_mutex_unlock(&policy_write_lock);
 assert(host_uid==0);*out=NULL;content_prepares++;
 if(content_prepare_error)return content_prepare_error;
 if(strncmp(source,"/fixture/",9)&&strcmp(source,"/proc/cpuinfo")&&strcmp(source,"/proc/meminfo")&&strcmp(source,"/proc/version")&&
    strcmp(source,"/proc/uptime")&&strcmp(source,"/proc/loadavg")&&strcmp(source,"/proc/stat")&&strcmp(source,"/proc/cmdline")&&strcmp(source,"/proc/bootconfig"))return-EOPNOTSUPP;
 if(!strcmp(target,"/bad"))return-EACCES;
 *out=kzalloc(sizeof(**out),GFP_KERNEL);if(!*out)return-ENOMEM;
 atomic_init(&(*out)->refs,1);(*out)->version=content_prepares;
 (*out)->regular=!strncmp(source,"/fixture/",9);(*out)->size=strstr(target,"long")?23:7;
 (*out)->source_generation=fixture_inode.i_generation;
 if(content_change_source)fixture_inode.i_generation++;
 content_live++;return 0;
}
static atomic_int stop_readers;
static atomic_ulong observations;
static int susfs_open_redirect_resolve_group(const char *a,const char *b,
 struct skp_group_redirect_object *r,struct kstatfs *s,void *x,void *y)
{ (void)a;(void)b;(void)x;(void)y;r->source.dev=10;r->source.ino=100;r->target.dev=11;r->target.ino=200;r->source_mnt_id=3;r->target_mnt_id=4;s->f_type=0x123;return 0; }
static bool susfs_mount_sequential_query(u64 c,u64 id,u64 parent,struct skp_mount_query_result *r)
{ (void)c;r->hidden=skp_policy_mount_path_hidden(id==4?"/fixture/child":"/else",NULL);r->shown_id=r->hidden?parent:id;return r->hidden; }
static struct skp_sequential_message message;
static struct file control;
static void as_root(void) { current=&owner;host_uid=0;host_accounting_uid=0; }
static void configure(u32 family,const char *path)
{
 memset(&message,0,sizeof(message));message.header=(struct skp_sequential_header){SKP_SEQUENTIAL_MAGIC,1,sizeof(message),SKP_SEQ_ADD_RULE,family,0};
 message.rule.subjects.version=1;message.rule.subjects.profile_count=1;message.rule.subjects.facts_generation=1;
 strcpy(message.rule.path,path);strcpy(message.rule.target,"/target");
 message.rule.values.flags=1;message.rule.values.ino=987;
}
static ssize_t submit(void) { loff_t o=0;return skp_policy_write(&control,(char *)&message,sizeof(message),&o); }
static void clear(u32 family) {
 struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_CLEAR_FAMILY,family,0};loff_t o=0;
 assert(skp_policy_write(&control,(char *)&h,sizeof(h),&o)==sizeof(h));
}
static void *reader(void *unused)
{
 (void)unused;current=&app;host_uid=10001;
 while(!atomic_load(&stop_readers)) {
  struct skp_kstat_query_result answer;bool hidden;
  enum skp_object_query_mode mode=skp_policy_kstat_query(10,100,&answer);
  assert(mode==SKP_OBJECT_UPSTREAM || (mode==SKP_OBJECT_GROUPED&&answer.matched&&answer.values.ino==987));
  skp_policy_paths_inode_override(&fixture_inode,&hidden);
  atomic_fetch_add(&observations,1);
 }
 return NULL;
}
static void test_dirent_filesystem_scope(void)
{
 bool hidden;
 fixture_sb.s_dev=245;fixture_inode.i_ino=467977;
 configure(SKP_SEQ_PATH,"/fixture");
 message.rule.subjects.whitelist_count=1;
 message.rule.subjects.whitelist[0]=10002;
 assert(submit()==sizeof(message));
 current=&app;host_uid=10001;
 assert(skp_policy_paths_dirent_override(245,467977,"fixture",&hidden)&&hidden);
 /* Android's FUSE listing and its backing filesystem may share ino/name.
  * A lower-filesystem daemon must never poison the shared FUSE reply. */
 assert(!skp_policy_paths_dirent_override(65103,467977,"fixture",&hidden)&&!hidden);
 host_uid=10002;
 assert(!skp_policy_paths_dirent_override(245,467977,"fixture",&hidden)&&!hidden);
 as_root();clear(SKP_SEQ_PATH);
 fixture_sb.s_dev=10;fixture_inode.i_ino=100;
}
static void test_path_contents(void)
{
 struct inode leaf = { .i_sb = &fixture_sb, .i_ino = 101, .i_mode = S_IFREG | 0644 };
 struct inode nested = { .i_sb = &fixture_sb, .i_ino = 102, .i_mode = S_IFDIR | 0755 };
 struct inode other = { .i_sb = &fixture_sb, .i_ino = 103, .i_mode = S_IFDIR | 0755 };
 struct super_block other_sb = { 77 };
 struct inode same_number = { .i_sb = &other_sb, .i_ino = 100, .i_mode = S_IFDIR | 0755 };
 struct dentry root = { .inode = &other }, nested_dentry = { .inode = &nested, .d_parent = &fixture_dentry };
 struct dentry leaf_dentry = { .inode = &leaf, .d_parent = &fixture_dentry };
 struct dentry deep_dentry = { .inode = &leaf, .d_parent = &nested_dentry };
 struct dentry hardlink = { .inode = &leaf, .d_parent = &root };
 struct dentry other_alias = { .inode = &same_number, .d_parent = &root };
 struct dentry other_leaf = { .inode = &leaf, .d_parent = &other_alias };
 bool hidden;
 root.d_parent = &root;
 fixture_dentry.d_parent = &root;
 fixture_inode.i_mode = S_IFDIR | 0755;
 as_root();configure(SKP_SEQ_PATH, "/fixture");
 message.header.command = SKP_SEQ_ADD_PATH_CONTENTS;
 message.rule.target[0] = 0;memset(&message.rule.values, 0, sizeof(message.rule.values));
 message.rule.subjects.whitelist_count = 1;message.rule.subjects.whitelist[0] = 10002;
 assert(submit() == sizeof(message));
 assert(counts[1] == 1 && path_contents_count == 1 && fixture_inode.refs == 1 && !fixture_inode.wrappers);
 current = &app;host_uid = 10001;
 assert(!skp_policy_paths_inode_override(&fixture_inode, &hidden) && !hidden);
 assert(!skp_policy_paths_dirent_override(10, 100, "fixture", &hidden) && !hidden);
 assert(!skp_policy_path_contents_hidden(&fixture_dentry, false));
 assert(skp_policy_path_contents_search_hidden(&fixture_inode));
 assert(skp_policy_path_contents_hidden(&fixture_dentry, true));
 assert(skp_policy_path_contents_hidden(&leaf_dentry, false));
 assert(skp_policy_path_contents_hidden(&nested_dentry, false));
 assert(skp_policy_path_contents_hidden(&deep_dentry, false));
 assert(skp_policy_path_contents_hidden(&nested_dentry, true));
 for (unsigned i = 0; i < 5; ++i) {
  unsigned int kinds[] = {S_IFLNK, S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK};
  leaf.i_mode = kinds[i];assert(skp_policy_path_contents_hidden(&leaf_dentry, false));
 }
 leaf.i_mode = S_IFREG | 0644;
 path_group_supported = false;
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 path_group_supported = true;

 assert(!skp_policy_path_contents_hidden(&hardlink, false));
 assert(!skp_policy_path_contents_search_hidden(&leaf));
 assert(!skp_policy_path_contents_search_hidden(&same_number));
 assert(!skp_policy_path_contents_hidden(&other_leaf, false));
 host_uid = 10002;
 assert(!skp_policy_path_contents_search_hidden(&fixture_inode));
 assert(!skp_policy_path_contents_hidden(&fixture_dentry, true));
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 as_root();
 {loff_t off=0;struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_REGISTER_MANAGER,0,0};
  assert(skp_policy_write(&control,(char*)&h,sizeof(h),&off)==sizeof(h));}
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 assert(!skp_policy_path_contents_search_hidden(&fixture_inode));
 assert(!skp_policy_release(NULL,&control));assert(!skp_policy_open(NULL,&control));
 /* Replacing the same rule switches modes without retaining both identities. */
 message.header.command = SKP_SEQ_ADD_RULE;
 assert(submit() == sizeof(message) && !path_contents_count && counts[1] == 1);
 assert(skp_policy_paths_inode_override(&fixture_inode, &hidden) && hidden);
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 message.header.command = SKP_SEQ_ADD_PATH_CONTENTS;
 assert(submit() == sizeof(message) && path_contents_count == 1);
 fixture_inode.i_mode = S_IFREG | 0644;
 assert(submit() == -ENOTDIR && counts[1] == 1 && path_contents_count == 1 && fixture_inode.refs == 1);
 fixture_inode.i_mode = S_IFDIR | 0755;
 path_contents_supported = false;assert(submit() == -EOPNOTSUPP && path_contents_count == 1);path_contents_supported = true;
 directory_names_ready = false;assert(submit() == sizeof(message) && path_contents_count == 1);directory_names_ready = true;
 message.header.family = SKP_SEQ_MAP;assert(submit() == -EINVAL);message.header.family = SKP_SEQ_PATH;
 message.rule.target[0] = 'x';assert(submit() == -EINVAL);message.rule.target[0] = 0;
 message.rule.values.ino = 1;assert(submit() == -EINVAL);message.rule.values.ino = 0;
 strcpy(message.rule.path, "relative");assert(submit() == -EINVAL);strcpy(message.rule.path, "/fixture");
 skp_policy_release_superblock(&fixture_sb);
 assert(!counts[1] && !path_contents_count && !fixture_inode.refs && !fixture_inode.wrappers);
 strcpy(message.rule.path, "/missing");message.header.flags = SKP_SEQ_ALLOW_PENDING;missing_created = false;
 assert(submit() == sizeof(message) && path_contents_count == 1 && credentials.refs == 1);
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 missing_created = true;skp_pending_work(&pending_work.work);
 assert(fixture_inode.refs == 1 && !fixture_inode.wrappers && !credentials.refs);
 assert(skp_policy_path_contents_hidden(&leaf_dentry, false));
 clear(SKP_SEQ_PATH);
 assert(!path_contents_count && !skp_policy_path_contents_present() && !fixture_inode.refs);
 assert(!skp_policy_path_contents_hidden(&leaf_dentry, false));
 fixture_dentry.d_parent = NULL;fixture_inode.i_mode = 0;missing_created = false;
 puts("PASS path contents: anchor visible; child/deep items hidden; outside hardlink/other filesystem visible; scopes/manager, mode replacement, directory validation, pending and cleanup");
}

static void test_directory_names(void)
{
 bool hidden;
 unsigned int refs = fixture_inode.refs;
 as_root();configure(SKP_SEQ_PATH,"bin.mt.plus");
 message.header.command=SKP_SEQ_ADD_DIR_NAME;
 memset(&message.rule.values,0,sizeof(message.rule.values));
 memset(message.rule.target,0,sizeof(message.rule.target));
 message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;
 assert(submit()==sizeof(message)&&directory_name_count==1&&counts[SKP_SEQ_PATH]==1);
 assert(fixture_inode.refs==refs&&!fixture_inode.wrappers); /* no resolution or inode pin */
 current=&app;host_uid=10001;
 assert(skp_policy_directory_name_hidden("bin.mt.plus"));
 assert(!skp_policy_directory_name_hidden("bin.mt.plus.backup"));
 assert(!skp_policy_directory_name_hidden("BIN.MT.PLUS"));
 assert(!skp_policy_paths_inode_override(&fixture_inode,&hidden)&&!hidden);
 assert(!skp_policy_paths_dirent_override(10,100,"bin.mt.plus",&hidden)&&!hidden);
 host_uid=10002;assert(!skp_policy_directory_name_hidden("bin.mt.plus"));
 as_root();assert(submit()==sizeof(message)&&directory_name_count==1&&counts[1]==1);
 {loff_t off=0;struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_REGISTER_MANAGER,0,0};
  assert(skp_policy_write(&control,(char*)&h,sizeof(h),&off)==sizeof(h));}
 assert(!skp_policy_directory_name_hidden("bin.mt.plus"));
 assert(skp_policy_release(NULL,&control)==0);assert(skp_policy_open(NULL,&control)==0);
 assert(skp_policy_directory_name_hidden("bin.mt.plus"));
 for(unsigned i=0;i<6;i++) {
  const char *bad[]={"", ".", "..", "a/b", "/", "/absolute"};
  strcpy(message.rule.path,bad[i]);assert(submit()==-EINVAL&&directory_name_count==1);
 }
 strcpy(message.rule.path,"bin.mt.plus");message.header.flags=SKP_SEQ_ALLOW_PENDING;
 assert(submit()==-EINVAL);message.header.flags=0;
 message.rule.target[0]='x';assert(submit()==-EINVAL);message.rule.target[0]=0;
 message.rule.values.ino=1;assert(submit()==-EINVAL);message.rule.values.ino=0;
 directory_names_ready=false;assert(submit()==-EOPNOTSUPP&&directory_name_count==1);directory_names_ready=true;
 /* Superblock teardown must not discard the inode-independent name rule. */
 skp_policy_release_superblock(&fixture_sb);assert(counts[1]==1&&directory_name_count==1);
 clear(SKP_SEQ_PATH);assert(!skp_policy_directory_names_present()&&!skp_policy_directory_name_hidden("bin.mt.plus"));
}
static void test_content_policy(void)
{
 struct path path={&fixture_dentry};struct susfs_content *old,*fresh;
 struct skp_redirect_query_result query;
 unsigned int prepares;
 fixture_inode.i_generation=1;
 configure(SKP_SEQ_REDIRECT,"/proc/cpuinfo");message.header.command=SKP_SEQ_ADD_CONTENT;
 assert(submit()==sizeof(message)&&counts[SKP_SEQ_REDIRECT]==1&&content_live==1);
 current=&app;host_uid=10001;
 assert(skp_policy_content_source_applies(&path));old=skp_policy_content_get(&path);assert(old&&old->refs==2);
 assert(skp_policy_redirect_query(10,100,0,0,SKP_REDIRECT_FORWARD,&query)==SKP_OBJECT_UPSTREAM&&!query.matched);
 assert(skp_policy_redirect_query(10,100,0,0,SKP_REDIRECT_REVERSE,&query)==SKP_OBJECT_UPSTREAM&&!query.matched);
 as_root();content_prepare_error=-EACCES;
 assert(submit()==-EACCES&&counts[SKP_SEQ_REDIRECT]==1&&content_live==1);content_prepare_error=0;
 assert(submit()==sizeof(message)&&content_live==2);
 current=&app;host_uid=10001;fresh=skp_policy_content_get(&path);
 assert(fresh&&fresh!=old&&fresh->version!=old->version&&old->refs==1);
 fixture_inode.i_generation=2;assert(!skp_policy_content_get(&path));fixture_inode.i_generation=1;
 as_root();clear(SKP_SEQ_REDIRECT);assert(content_live==2);
 assert(!skp_policy_content_source_applies(&path));susfs_content_put(old);susfs_content_put(fresh);assert(!content_live);
 content_change_source=true;
 assert(submit()==-ESTALE&&!content_live&&!counts[SKP_SEQ_REDIRECT]);content_change_source=false;fixture_inode.i_generation=1;
 prepares=content_prepares;content_supported=false;
 assert(submit()==-EOPNOTSUPP&&content_prepares==prepares&&!content_live);
 /* 6.6 disables only content replacement. Ordinary path redirects still
  * take their original resolver/hook route, even with content unavailable. */
 message.header.command=SKP_SEQ_ADD_RULE;
 assert(submit()==sizeof(message)&&counts[SKP_SEQ_REDIRECT]==1);
 assert(content_prepares==prepares&&!content_live);
 current=&app;host_uid=10001;
 assert(skp_policy_redirect_query(10,100,0,0,SKP_REDIRECT_FORWARD,&query)==SKP_OBJECT_GROUPED&&query.matched);
 assert(!skp_policy_content_source_applies(&path));
 as_root();clear(SKP_SEQ_REDIRECT);
 message.header.command=SKP_SEQ_ADD_CONTENT;content_supported=true;
 message.header.family=SKP_SEQ_PATH;assert(submit()==-EINVAL&&content_prepares==prepares);
 message.header.family=SKP_SEQ_REDIRECT;message.rule.reserved=1;assert(submit()==-EINVAL&&content_prepares==prepares);
 message.rule.reserved=0;strcpy(message.rule.path,"/proc/not-supported");assert(submit()==-EOPNOTSUPP&&!content_live);
 configure(SKP_SEQ_REDIRECT,"/proc/cpuinfo");message.header.command=SKP_SEQ_ADD_CONTENT;
 message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;
 assert(submit()==sizeof(message));current=&app;host_uid=10002;
 assert(!skp_policy_content_source_applies(&path));as_root();clear(SKP_SEQ_REDIRECT);
 assert(!content_live);fixture_inode.i_generation=0;
}
static void test_mixed_redirect_order(void)
{
 struct path path={&fixture_dentry};struct susfs_content *content;
 struct skp_redirect_query_result query;
 configure(SKP_SEQ_REDIRECT,"/proc/cpuinfo");assert(submit()==sizeof(message));
 message.header.command=SKP_SEQ_ADD_CONTENT;message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;
 assert(submit()==sizeof(message));current=&app;host_uid=10001;
 assert(!skp_policy_content_get(&path));
 assert(skp_policy_redirect_query(10,100,0,0,SKP_REDIRECT_FORWARD,&query)==SKP_OBJECT_GROUPED&&query.matched);
 as_root();clear(SKP_SEQ_REDIRECT);
 configure(SKP_SEQ_REDIRECT,"/proc/cpuinfo");message.header.command=SKP_SEQ_ADD_CONTENT;
 message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;assert(submit()==sizeof(message));
 configure(SKP_SEQ_REDIRECT,"/proc/cpuinfo");assert(submit()==sizeof(message));
 current=&app;host_uid=10001;content=skp_policy_content_get(&path);assert(content);susfs_content_put(content);
 as_root();clear(SKP_SEQ_REDIRECT);assert(!content_live);
}
static void test_expanded_content_size(void)
{
 struct path path={&fixture_dentry};struct susfs_content *old;
 u64 size=999;
 configure(SKP_SEQ_REDIRECT,"/fixture/plain");message.header.command=SKP_SEQ_ADD_CONTENT;
 assert(submit()==sizeof(message));current=&app;host_uid=10001;
 old=skp_policy_content_get(&path);assert(old&&susfs_content_is_regular(old));
 assert(fixture_inode.refs==1);
 assert(skp_policy_content_stat_size(10,100,&size)&&size==7);
 assert(!skp_policy_content_stat_size(11,100,&size));
 fixture_inode.i_generation++;
 assert(!skp_policy_content_stat_size(10,100,&size));fixture_inode.i_generation--;
 as_root();strcpy(message.rule.target,"/long");assert(submit()==sizeof(message));
 current=&app;host_uid=10001;
 assert(skp_policy_content_stat_size(10,100,&size)&&size==23&&susfs_content_size(old)==7);
 as_root();skp_policy_release_superblock(&fixture_sb);
 assert(!counts[SKP_SEQ_REDIRECT]&&fixture_inode.refs==0&&content_live==1);
 assert(!skp_policy_content_stat_size(10,100,&size));susfs_content_put(old);assert(!content_live);
 const char *names[]={"/proc/uptime","/proc/loadavg","/proc/stat","/proc/cmdline","/proc/bootconfig"};
 for(unsigned int i=0;i<sizeof(names)/sizeof(names[0]);++i){
  configure(SKP_SEQ_REDIRECT,names[i]);message.header.command=SKP_SEQ_ADD_CONTENT;assert(submit()==sizeof(message));
  current=&app;host_uid=10001;assert(skp_policy_content_source_applies(&path));
  assert(!skp_policy_content_stat_size(10,100,&size));as_root();clear(SKP_SEQ_REDIRECT);
 }
 configure(SKP_SEQ_REDIRECT,"/fixture/plain");assert(submit()==sizeof(message));
 message.header.command=SKP_SEQ_ADD_CONTENT;message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;
 assert(submit()==sizeof(message));current=&app;host_uid=10001;
 assert(!skp_policy_content_stat_size(10,100,&size));as_root();clear(SKP_SEQ_REDIRECT);
 assert(!content_live);
}
static void expect_selected_root_rules(bool expected)
{
 bool hidden=false;struct skp_kstat_query_result kstat;struct skp_map_query_result map;
 struct skp_redirect_query_result redirect;
 assert(skp_policy_paths_inode_override(&fixture_inode,&hidden)==expected&&hidden==expected);
 assert(skp_policy_paths_dirent_override(10,100,"fixture",&hidden)==expected&&hidden==expected);
 (void)skp_policy_kstat_query(10,100,&kstat);assert(!!kstat.matched==expected);
 (void)skp_policy_map_query(10,100,&map);assert(!!map.hidden==expected);
 (void)skp_policy_redirect_query(10,100,0,3,SKP_REDIRECT_FORWARD,&redirect);assert(!!redirect.matched==expected);
 assert(skp_policy_mount_path_hidden("/fixture/child",NULL)==expected);
 assert(skp_policy_directory_name_hidden("root-only")==expected);
}
static void test_root_application_scope(void)
{
 for(unsigned family=SKP_SEQ_PATH;family<=SKP_SEQ_MOUNT;family++) {
  configure(family,"/fixture");
  message.rule.subjects.mode=SKP_SUBJECT_BLACKLIST;
  message.rule.subjects.flags=SKP_SUBJECT_EXEMPT_ALL;
  message.rule.subjects.blacklist_count=1;message.rule.subjects.blacklist[0]=10001;
  assert(submit()==sizeof(message));
 }
 configure(SKP_SEQ_PATH,"root-only");message.header.command=SKP_SEQ_ADD_DIR_NAME;
 message.rule.target[0]=0;memset(&message.rule.values,0,sizeof(message.rule.values));
 message.rule.subjects.mode=SKP_SUBJECT_BLACKLIST;message.rule.subjects.flags=SKP_SUBJECT_EXEMPT_ALL;
 message.rule.subjects.blacklist_count=1;message.rule.subjects.blacklist[0]=10001;
 assert(submit()==sizeof(message));
 current=&app;host_uid=0;host_accounting_uid=10001;expect_selected_root_rules(true);
 host_accounting_uid=10002;expect_selected_root_rules(false);
 host_accounting_uid=0;expect_selected_root_rules(false);
 host_accounting_uid=110001;expect_selected_root_rules(false);
 host_uid=10001;host_accounting_uid=10002;expect_selected_root_rules(true);
 as_root();host_accounting_uid=10001;
 {loff_t offset=0;struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_REGISTER_MANAGER,0,0};
  assert(skp_policy_write(&control,(char*)&h,sizeof(h),&offset)==sizeof(h));}
 expect_selected_root_rules(false);
 current=&child;host_uid=0;expect_selected_root_rules(true);
 as_root();assert(!skp_policy_release(NULL,&control));assert(!skp_policy_open(NULL,&control));
 for(unsigned family=SKP_SEQ_PATH;family<=SKP_SEQ_MOUNT;family++)clear(family);
 assert(!directory_name_count&&!content_live);
}

int main(void)
{
 bool hidden,applies=true;loff_t offset=0;pthread_t readers[4];
 owner.group_leader=&owner;app.group_leader=&app;child.group_leader=&child;as_root();
 assert(skp_policy_adapter_init()==0);assert(skp_policy_open(NULL,&control)==0);
 test_root_application_scope();
 test_content_policy();
 test_mixed_redirect_order();
 test_expanded_content_size();
 test_dirent_filesystem_scope();
 test_directory_names();
 test_path_contents();
 configure(SKP_SEQ_PATH,"/fixture");assert(submit()==sizeof(message));assert(fixture_inode.refs==1&&fixture_inode.wrappers==1);
 configure(SKP_SEQ_KSTAT,"/fixture");assert(submit()==sizeof(message));assert(counts[1]==1&&counts[2]==1);
 configure(SKP_SEQ_MAP,"/bad");assert(submit()==-EACCES);assert(counts[1]==1&&counts[2]==1&&counts[3]==0);
 configure(SKP_SEQ_MAP,"/fixture");assert(submit()==sizeof(message));
 clear(SKP_SEQ_KSTAT);assert(counts[1]==1&&counts[2]==0&&counts[3]==1);
 assert(!skp_policy_override(&applies));assert(skp_policy_paths_inode_override(&fixture_inode,&hidden)&&hidden);
 { struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_REGISTER_MANAGER,0,0};
  assert(skp_policy_write(&control,(char *)&h,sizeof(h),&offset)==sizeof(h)); }
 assert(skp_policy_override(&applies)&&!applies);
 assert(!skp_policy_paths_inode_override(&fixture_inode,&hidden));
 assert(!skp_policy_paths_dirent_override(10,100,"fixture",&hidden)&&!hidden);
 current=&child;assert(skp_policy_paths_inode_override(&fixture_inode,&hidden)&&hidden);as_root();
 assert(skp_policy_release(NULL,&control)==0);assert(counts[1]==1&&counts[3]==1);
 assert(skp_policy_paths_inode_override(&fixture_inode,&hidden)&&hidden);assert(owner.refs==0);
 assert(skp_policy_open(NULL,&control)==0);
 clear(SKP_SEQ_PATH);assert(fixture_inode.refs==0&&fixture_inode.wrappers==0);
 configure(SKP_SEQ_PATH,"/missing");message.header.flags=SKP_SEQ_ALLOW_PENDING;
 assert(submit()==sizeof(message));assert(fixture_inode.refs==0&&credentials.refs==1);
 missing_created=true;skp_pending_work(&pending_work.work);
 assert(fixture_inode.refs==1&&fixture_inode.wrappers==1&&credentials.refs==0);
 skp_policy_release_superblock(&fixture_sb);assert(counts[1]==0&&fixture_inode.refs==0&&fixture_inode.wrappers==0);
 configure(SKP_SEQ_MOUNT,"/fixture");assert(submit()==sizeof(message));
 assert(skp_policy_mount_path_hidden("/fixture/child",NULL));
 assert(!skp_policy_mount_path_hidden("/fixture-other",NULL));
 clear(SKP_SEQ_MOUNT);
 configure(SKP_SEQ_KSTAT,"/fixture");
 pthread_mutex_lock(&policy_write_lock);assert(submit()==-EBUSY);pthread_mutex_unlock(&policy_write_lock);
 for(int i=0;i<4;i++)assert(!pthread_create(&readers[i],NULL,reader,NULL));
 for(int i=0;i<1500;i++) {
  configure(SKP_SEQ_KSTAT,"/fixture");assert(submit()==sizeof(message));
  configure(SKP_SEQ_PATH,"/fixture");assert(submit()==sizeof(message));
  clear(SKP_SEQ_KSTAT);clear(SKP_SEQ_PATH);
 }
 atomic_store(&stop_readers,1);for(int i=0;i<4;i++)pthread_join(readers[i],NULL);
 assert(observations>0);assert(fixture_inode.refs==0&&fixture_inode.wrappers==0);
 assert(skp_policy_release(NULL,&control)==0);skp_policy_adapter_exit();
 assert(allocations==0&&credentials.refs==0&&owner.refs==0);
 printf("PASS sequential adapter: filesystem-scoped dirents, exempt apps, partial success, family isolation, exact manager lifecycle, pending resolution, superblock cleanup, busy rejection; concurrent observations=%lu allocations=%d\n",(unsigned long)observations,(int)allocations);
 return 0;
}
