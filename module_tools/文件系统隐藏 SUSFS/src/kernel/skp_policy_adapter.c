// SPDX-License-Identifier: GPL-2.0-only
/* One rule per write. Publication is only the lifetime boundary of that rule;
 * clearing a family and adding its successors are deliberately separate. */
#ifdef SKP_SEQUENTIAL_HOSTTEST
#include "../tools/tests/sequential_shim.h"
#else
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/user.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#endif
#include "skp_policy_adapter.h"
#include "susfs_content.h"
#ifndef SKP_SEQUENTIAL_HOSTTEST
#include "susfs.h"
#include "susfs_dirent.h"
#include "susfs_dir_name.h"
#endif

struct skp_selector {
 struct list_head list;
 unsigned int references;
 struct skp_subject_policy policy;
};
struct skp_rule {
 struct list_head list;
 struct list_head retired;
 struct skp_selector *selector;
 u32 family, profile_id, flags;
 unsigned int pending_attempt;
 char path[SKP_GROUP_PATH_LEN], target[SKP_GROUP_PATH_LEN];
 struct skp_kstat_values values;
 struct inode *inode;
 const struct cred *pending_cred;
 u64 dev, ino;
 char name[SKP_GROUP_PATH_LEN];
 struct skp_group_redirect_object redirect;
 struct kstatfs source_statfs;
 struct susfs_content *content;
 bool readlink_armed;
 bool directory_name;
 bool contents_only;
};
struct skp_policy_session {
 struct list_head list;
 struct task_struct *leader;
 bool registered;
};
static LIST_HEAD(path_rules);
static LIST_HEAD(kstat_rules);
static LIST_HEAD(map_rules);
static LIST_HEAD(redirect_rules);
static LIST_HEAD(mount_rules);
static struct list_head *const rules[] = {
 NULL, &path_rules, &kstat_rules, &map_rules, &redirect_rules, &mount_rules
};
static const u32 capacities[] = { 0, 8192, 32, 64, 64, 64 };
static u32 counts[SKP_SEQ_FAMILY_COUNT + 1];
static u32 directory_name_count;
static u32 path_contents_count;
static LIST_HEAD(selectors);
static LIST_HEAD(manager_sessions);
static DEFINE_MUTEX(policy_write_lock);
static struct proc_dir_entry *policy_node;
static bool stopping;
static struct task_struct *resolving_task;
static unsigned int pending_passes;
static unsigned int pending_cycle = 1;
static void skp_pending_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(pending_work, skp_pending_work);

static bool skp_current_manager(void)
{
 struct skp_policy_session *session;
 if (READ_ONCE(resolving_task) == current)
  return true;
 list_for_each_entry_rcu(session, &manager_sessions, list)
  if (session->leader == current->group_leader)
   return true;
 return false;
}
static bool skp_rule_applies(const struct skp_rule *rule)
{
 struct skp_subject_context context = { .actual_uid = current_uid().val };
 struct skp_subject_decision answer;
 /* SKP su retains the original credential's user account after changing
  * all access UIDs to 0. Package matching follows that exact account;
  * never assign arbitrary root processes to a selected application. */
 if (!context.actual_uid && current_user_ns() == &init_user_ns)
  context.accounting_uid = current_user()->uid.val;
 context.precise_manager = skp_current_manager();
 answer = skp_subject_evaluate(&rule->selector->policy, &context);
 return answer.applies && answer.profile_id == rule->profile_id;
}
bool skp_policy_override(bool *applies)
{
 bool manager;
 rcu_read_lock();
 manager = skp_current_manager();
 rcu_read_unlock();
 if (manager)
  *applies = false;
 return manager;
}
/* Legacy tables remain independent and mutable. This formerly meant an
 * exclusive whole-policy mode; sequential PLUS rules never enter that mode. */
bool skp_policy_paths_active(void) { return false; }
bool skp_policy_paths_present(void) { return READ_ONCE(counts[SKP_SEQ_PATH]) != 0; }
bool skp_policy_directory_names_present(void) { return READ_ONCE(directory_name_count) != 0; }
bool skp_policy_path_contents_present(void) { return READ_ONCE(path_contents_count) != 0; }
/* Follow only actual ancestry, never textual prefixes or arbitrary regular-file
 * aliases. The caller owns the starting dentry; RCU protects ancestors while
 * each d_lock supplies a coherent inode/parent snapshot. Rules hold the anchor
 * inode, so matching its filesystem identity cannot be recycled during use.
 * Like ordinary path rules this does not cross mount roots into another tree. */
bool skp_policy_path_contents_hidden(const struct dentry *dentry, bool include_self)
{
 const struct dentry *cursor = dentry;
 struct skp_rule *rule;
 unsigned int depth = 0;
 bool hidden = false;
 if (!cursor || !skp_policy_path_contents_present() || !sus_path_group_supported())
  return false;
 rcu_read_lock();
 while (cursor && depth++ < 4096) {
  struct dentry *entry = (struct dentry *)cursor;
  struct dentry *parent;
  struct inode *inode;
  u64 dev = 0, ino = 0;
  spin_lock(&entry->d_lock);
  parent = READ_ONCE(entry->d_parent);
  inode = d_inode(entry);
  if (inode && inode->i_sb) {
   dev = (u64)inode->i_sb->s_dev;
   ino = (u64)READ_ONCE(inode->i_ino);
  }
  spin_unlock(&entry->d_lock);
  if (include_self || cursor != dentry) {
   list_for_each_entry_rcu(rule, &path_rules, list) {
    if (rule->contents_only && rule->inode && rule->dev == dev &&
        rule->ino == ino && skp_rule_applies(rule)) {
     hidden = true;
     goto out;
    }
   }
  }
  if (parent == cursor)
   break;
  cursor = parent;
 }
out:
 rcu_read_unlock();
 return hidden;
}
bool skp_policy_directory_name_hidden(const char *name)
{
 struct skp_rule *rule;
 bool hidden = false;
 if (!name || !skp_policy_directory_names_present())
  return false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &path_rules, list) {
  if (rule->directory_name && !strcmp(rule->path, name) && skp_rule_applies(rule)) {
   hidden = true;
   break;
  }
 }
 rcu_read_unlock();
 return hidden;
}
bool skp_policy_redirects_active(void) { return READ_ONCE(counts[SKP_SEQ_REDIRECT]) != 0; }
bool skp_policy_mounts_active(void) { return READ_ONCE(counts[SKP_SEQ_MOUNT]) != 0; }

/* Match only the retained directory identity. The existing inode_permission
 * hook uses this to reject lookup below the anchor without hiding the anchor.
 * It does not need file_open, a directory alias, or new LSM registrations. */
bool skp_policy_path_contents_search_hidden(struct inode *inode)
{
 struct skp_rule *rule;
 bool hidden = false;
 if (!inode || !inode->i_sb || !S_ISDIR(READ_ONCE(inode->i_mode)) ||
     !skp_policy_path_contents_present() || !sus_path_group_supported())
  return false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &path_rules, list) {
  if (rule->contents_only && rule->inode && rule->dev == (u64)inode->i_sb->s_dev &&
      rule->ino == (u64)READ_ONCE(inode->i_ino) && skp_rule_applies(rule)) {
   hidden = true;
   break;
  }
 }
 rcu_read_unlock();
 return hidden;
}

bool skp_policy_paths_inode_override(struct inode *inode, bool *hidden)
{
 struct skp_rule *rule;
 bool matched = false;
 *hidden = false;
 if (!inode || !inode->i_sb)
  return false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &path_rules, list) {
  if (!rule->contents_only && rule->inode && rule->dev == (u64)inode->i_sb->s_dev &&
      rule->ino == (u64)READ_ONCE(inode->i_ino) && skp_rule_applies(rule)) {
   *hidden = matched = true;
   break;
  }
 }
 rcu_read_unlock();
 return matched;
}
bool skp_policy_paths_dirent_override(u64 dev, u64 ino, const char *name, bool *hidden)
{
 struct skp_rule *rule;
 bool matched = false;
 *hidden = false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &path_rules, list) {
  if (!rule->contents_only && rule->inode && rule->dev == dev && rule->ino == ino && name && !strcmp(rule->name, name) &&
      skp_rule_applies(rule)) {
   *hidden = matched = true;
   break;
  }
 }
 rcu_read_unlock();
 return matched;
}
static bool skp_redirect_matches(const struct skp_rule *rule, u64 dev, u64 ino,
 u32 igen, u64 mnt_id, u32 direction)
{
 const struct skp_redirect_key *key = direction == SKP_REDIRECT_FORWARD ?
  &rule->redirect.source : &rule->redirect.target;
 if (rule->content || !skp_rule_applies(rule) || key->ino != ino)
  return false;
 if (direction == SKP_REDIRECT_IDS)
  return mnt_id && rule->redirect.target_mnt_id == mnt_id;
 return key->dev == dev && (!key->igen || key->igen == igen);
}
static bool skp_source_matches(const struct skp_rule *rule, const struct inode *inode)
{
 const struct skp_redirect_key *key = &rule->redirect.source;
 return inode && inode->i_sb && key->dev == (u64)inode->i_sb->s_dev &&
  key->ino == (u64)READ_ONCE(inode->i_ino) &&
  (!key->igen || key->igen == READ_ONCE(inode->i_generation)) && skp_rule_applies(rule);
}
struct susfs_content *skp_policy_content_get(const struct path *path)
{
 struct skp_rule *rule;
 struct susfs_content *content = NULL;
 struct inode *inode;
 if (!path || !path->dentry || !skp_policy_redirects_active())
  return NULL;
 inode = d_inode(path->dentry);
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &redirect_rules, list) {
  if (!skp_source_matches(rule, inode))
   continue;
  /* Preserve the same first-applicable-rule order as ordinary redirects.
   * A later content rule must not override an earlier path rule. */
  content = rule->content;
  if (content)
   susfs_content_get(content);
  break;
 }
 rcu_read_unlock();
 return content;
}
bool skp_policy_content_source_applies(const struct path *path)
{
 struct susfs_content *content = skp_policy_content_get(path);
 if (!content)
  return false;
 susfs_content_put(content);
 return true;
}
bool skp_policy_content_stat_size(u64 dev, u64 ino, u64 *size)
{
 struct skp_rule *rule;
 bool found = false;
 if (!size || !skp_policy_redirects_active())
  return false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &redirect_rules, list) {
  if (rule->redirect.source.dev != dev || rule->redirect.source.ino != ino ||
      !skp_rule_applies(rule))
   continue;
  if (rule->content && rule->inode && susfs_content_is_regular(rule->content) &&
      rule->redirect.source.igen == READ_ONCE(rule->inode->i_generation)) {
   *size = susfs_content_size(rule->content);
   found = true;
  }
  break;
 }
 rcu_read_unlock();
 return found;
}
static bool skp_reverse_owns(u64 dev, u64 ino, u32 igen)
{
 struct skp_rule *rule;
 list_for_each_entry_rcu(rule, &redirect_rules, list)
  if (skp_redirect_matches(rule, dev, ino, igen, 0, SKP_REDIRECT_REVERSE))
   return true;
 return false;
}
static enum skp_object_query_mode skp_kstat_query(u64 dev, u64 ino, u32 igen,
 bool maps, struct skp_kstat_query_result *result)
{
 struct skp_rule *rule;
 enum skp_object_query_mode mode = SKP_OBJECT_UPSTREAM;
 memset(result, 0, sizeof(*result));
 rcu_read_lock();
 if (skp_current_manager() || (maps && skp_reverse_owns(dev, ino, igen))) {
  mode = SKP_OBJECT_GROUPED;
  goto out;
 }
 list_for_each_entry_rcu(rule, &kstat_rules, list)
  if (rule->dev == dev && rule->ino == ino && skp_rule_applies(rule)) {
   result->matched = 1;
   result->values = rule->values;
   mode = SKP_OBJECT_GROUPED;
   break;
  }
out:
 rcu_read_unlock();
 return mode;
}
enum skp_object_query_mode skp_policy_kstat_query(u64 dev, u64 ino,
 struct skp_kstat_query_result *result)
{ return skp_kstat_query(dev, ino, 0, false, result); }
enum skp_object_query_mode skp_policy_kstat_maps_query(u64 dev, u64 ino, u32 igen,
 struct skp_kstat_query_result *result)
{ return skp_kstat_query(dev, ino, igen, true, result); }
enum skp_object_query_mode skp_policy_map_query(u64 dev, u64 ino,
 struct skp_map_query_result *result)
{
 struct skp_rule *rule;
 enum skp_object_query_mode mode = SKP_OBJECT_UPSTREAM;
 memset(result, 0, sizeof(*result));
 rcu_read_lock();
 if (skp_current_manager())
  mode = SKP_OBJECT_GROUPED;
 else list_for_each_entry_rcu(rule, &map_rules, list)
  if (rule->dev == dev && rule->ino == ino && skp_rule_applies(rule)) {
   result->hidden = 1;
   mode = SKP_OBJECT_GROUPED;
   break;
  }
 rcu_read_unlock();
 return mode;
}
static bool skp_prefix(const char *value, const char *prefix)
{
 size_t n;
 if (!value || !prefix)
  return false;
 n = strlen(prefix);
 return n && !strncmp(value, prefix, n) &&
  (prefix[n - 1] == '/' || !value[n] || value[n] == '/');
}
bool skp_policy_mount_path_hidden(const char *path, const char *devname)
{
 struct skp_rule *rule;
 bool hidden = false;
 rcu_read_lock();
 list_for_each_entry_rcu(rule, &mount_rules, list)
  if ((skp_prefix(path, rule->path) || skp_prefix(devname, rule->path)) &&
      skp_rule_applies(rule)) {
   hidden = true;
   break;
  }
 rcu_read_unlock();
 return hidden;
}
enum skp_object_query_mode skp_policy_mount_query(u64 cookie, u64 id, u64 parent_id,
 struct skp_mount_query_result *result)
{
 bool manager;
 memset(result, 0, sizeof(*result));
 rcu_read_lock();
 manager = skp_current_manager();
 rcu_read_unlock();
 if (manager)
  return SKP_OBJECT_GROUPED;
 if (!skp_policy_mounts_active())
  return SKP_OBJECT_UPSTREAM;
 return susfs_mount_sequential_query(cookie, id, parent_id, result) ?
  SKP_OBJECT_GROUPED : SKP_OBJECT_UPSTREAM;
}
enum skp_object_query_mode skp_policy_redirect_query(u64 dev, u64 ino, u32 igen,
 u64 mnt_id, u32 direction, struct skp_redirect_query_result *result)
{
 struct skp_rule *rule;
 enum skp_object_query_mode mode = SKP_OBJECT_UPSTREAM;
 memset(result, 0, sizeof(*result));
 rcu_read_lock();
 if (skp_current_manager()) {
  mode = SKP_OBJECT_GROUPED;
  goto out;
 }
 list_for_each_entry_rcu(rule, &redirect_rules, list) {
  if (!skp_redirect_matches(rule, dev, ino, igen, mnt_id, direction))
   continue;
  result->matched = 1;
  strscpy(result->path, direction == SKP_REDIRECT_FORWARD ? rule->target : rule->path,
   sizeof(result->path));
  strscpy(result->target_path, rule->target, sizeof(result->target_path));
  result->source_dev = rule->redirect.source.dev;
  result->source_ino = rule->redirect.source.ino;
  result->source_mnt_id = rule->redirect.source_mnt_id;
  result->source_statfs = rule->source_statfs;
  mode = SKP_OBJECT_GROUPED;
  break;
 }
out:
 rcu_read_unlock();
 return mode;
}
enum skp_object_query_mode skp_policy_fdinfo_query(u64 ino, u64 mnt_id,
 struct skp_fdinfo_query_result *result)
{
 struct skp_rule *rule;
 struct skp_mount_query_result mount;
 enum skp_object_query_mode mode = SKP_OBJECT_UPSTREAM;
 memset(result, 0, sizeof(*result));
 result->ino = ino;
 result->mnt_id = mnt_id;
 rcu_read_lock();
 if (skp_current_manager()) {
  mode = SKP_OBJECT_GROUPED;
  goto out;
 }
 list_for_each_entry_rcu(rule, &redirect_rules, list)
  if (skp_redirect_matches(rule, 0, ino, 0, mnt_id, SKP_REDIRECT_IDS)) {
   result->ino = rule->redirect.source.ino;
   result->mnt_id = rule->redirect.source_mnt_id;
   result->rewrite_ino = 1;
   mode = SKP_OBJECT_GROUPED;
   break;
  }
out:
 rcu_read_unlock();
 if (mode != SKP_OBJECT_GROUPED || result->rewrite_ino) {
  if (skp_policy_mount_query(0, result->mnt_id, 0, &mount) == SKP_OBJECT_GROUPED) {
   if (mount.shown_id)
    result->mnt_id = mount.shown_id;
   mode = SKP_OBJECT_GROUPED;
  }
 }
 return mode;
}

static struct skp_selector *skp_selector_get(const struct skp_subject_policy *policy)
{
 struct skp_selector *selector;
 list_for_each_entry(selector, &selectors, list)
  if (!memcmp(&selector->policy, policy, sizeof(*policy))) {
   selector->references++;
   return selector;
  }
 selector = kvmalloc(sizeof(*selector), GFP_KERNEL);
 if (!selector)
  return NULL;
 selector->references = 1;
 selector->policy = *policy;
 list_add_tail(&selector->list, &selectors);
 return selector;
}
static void skp_rule_free(struct skp_rule *rule)
{
 if (rule->content)
  susfs_content_put(rule->content);
 if (rule->readlink_armed) {
  sus_path_group_write_begin();
  sus_path_group_disarm_readlink_locked(rule->inode);
  sus_path_group_write_end();
 }
 if (rule->inode)
  iput(rule->inode);
 if (rule->pending_cred)
  put_cred(rule->pending_cred);
 if (rule->selector && !--rule->selector->references) {
  list_del(&rule->selector->list);
  kvfree(rule->selector);
 }
 kvfree(rule);
}
static int skp_resolve(struct skp_rule *rule)
{
 struct path path;
 struct inode *inode;
 int result;
 if (rule->family == SKP_SEQ_MOUNT)
  return 0; /* Prefixes also cover future mounts and namespace clones. */
 if (rule->family == SKP_SEQ_REDIRECT && !rule->content)
  return susfs_open_redirect_resolve_group(rule->path, rule->target,
   &rule->redirect, &rule->source_statfs, NULL, NULL);
 result = kern_path(rule->path, LOOKUP_FOLLOW, &path);
 if (result)
  return result;
 inode = d_inode(path.dentry);
 if (!inode) {
  path_put(&path);
  return -ENOENT;
 }
 if (rule->contents_only && !S_ISDIR(READ_ONCE(inode->i_mode))) {
  path_put(&path);
  return -ENOTDIR;
 }
 if (rule->content && !susfs_content_matches_source(rule->content, &path)) {
  path_put(&path);
  return -ESTALE;
 }
 rule->dev = inode->i_sb->s_dev;
 rule->ino = READ_ONCE(inode->i_ino);
 if (rule->content) {
  rule->redirect.source.dev = rule->dev;
  rule->redirect.source.ino = rule->ino;
  rule->redirect.source.igen = READ_ONCE(inode->i_generation);
  if (susfs_content_is_regular(rule->content)) {
   /* stat has no generation field. Retaining this inode prevents a deleted
    * source's number from being reused for an unrelated path-size answer.
    * The existing superblock watch drops this reference before teardown. */
   rule->inode = igrab(inode);
   if (!rule->inode) {
    path_put(&path);
    return -ESTALE;
   }
   result = sus_path_group_watch_inode(inode);
   if (result) {
    path_put(&path);
    return result;
   }
  }
 }
 if (rule->family == SKP_SEQ_PATH) {
  rule->inode = igrab(inode);
  if (!rule->inode) {
   path_put(&path);
   return -ESTALE;
  }
  spin_lock(&path.dentry->d_lock);
  result = strscpy(rule->name, path.dentry->d_name.name, sizeof(rule->name));
  spin_unlock(&path.dentry->d_lock);
  if (result < 0) {
   path_put(&path);
   return result;
  }
  result = sus_path_group_watch_inode(inode);
  if (result) {
   path_put(&path);
   return result;
  }
  /* no_extra preserves the upstream choice to leave readlink unwrapped. */
  if (!rule->contents_only && sus_path_group_supported()) {
   sus_path_group_write_begin();
   result = sus_path_group_arm_readlink_locked(inode);
   sus_path_group_write_end();
   if (result) {
    path_put(&path);
    return result;
   }
   rule->readlink_armed = true;
  }
 }
 path_put(&path);
 return 0;
}
static int skp_prepare_route(u32 family)
{
 int result = 0;
 switch (family) {
 case SKP_SEQ_KSTAT:
  susfs_kstat_group_write_begin();
  result = susfs_kstat_group_prepare_locked();
  susfs_kstat_group_write_end();
  break;
 case SKP_SEQ_MAP:
  susfs_map_group_write_begin();
  result = susfs_map_group_prepare_locked();
  susfs_map_group_write_end();
  break;
 case SKP_SEQ_REDIRECT:
  susfs_open_redirect_group_write_begin();
  result = susfs_open_redirect_group_prepare_locked(true);
  susfs_open_redirect_group_write_end();
  break;
 case SKP_SEQ_MOUNT:
  susfs_mount_group_write_begin();
  result = susfs_mount_group_prepare_locked();
  susfs_mount_group_write_end();
  /* Keep combined fdinfo ownership, but do not require optional routes. */
  susfs_open_redirect_group_write_begin();
  susfs_open_redirect_group_prepare_locked(false);
  susfs_open_redirect_group_write_end();
  break;
 }
 return result;
}
static int skp_validate_add(const struct skp_sequential_message *message)
{
 const struct skp_sequential_rule *input = &message->rule;
 unsigned int i;
 if (skp_subject_policy_validate(&input->subjects) || input->reserved ||
     !input->path[0] || !memchr(input->path, 0, sizeof(input->path)) ||
     (message->header.family == SKP_SEQ_REDIRECT &&
      (!input->target[0] || !memchr(input->target, 0, sizeof(input->target)))))
  return -EINVAL;
 for (i = 0; i < input->subjects.profile_count; i++)
  if (input->subjects.profiles[i] == input->profile_id)
   break;
 if (i == input->subjects.profile_count)
  return -EINVAL;
 if (message->header.command == SKP_SEQ_ADD_PATH_CONTENTS) {
  struct skp_kstat_values zero = {};
  if (message->header.family != SKP_SEQ_PATH || input->path[0] != '/' ||
      input->target[0] || memcmp(&input->values, &zero, sizeof(zero)))
   return -EINVAL;
 }
 if (message->header.command == SKP_SEQ_ADD_DIR_NAME) {
  struct skp_kstat_values zero = {};
  if (message->header.family != SKP_SEQ_PATH || message->header.flags ||
      strchr(input->path, '/') || !strcmp(input->path, ".") ||
      !strcmp(input->path, "..") || input->target[0] ||
      memcmp(&input->values, &zero, sizeof(zero)))
   return -EINVAL;
 }
 return 0;
}
static int skp_add(const struct skp_sequential_message *message,
 struct susfs_content *content)
{
 const struct skp_sequential_rule *input = &message->rule;
 struct skp_rule *rule, *previous = NULL, *item;
 int result = skp_validate_add(message);
 if (result)
  return result;
 if ((message->header.command == SKP_SEQ_ADD_CONTENT) != !!content)
  return -EINVAL;
 rule = kvzalloc(sizeof(*rule), GFP_KERNEL);
 if (!rule)
  return -ENOMEM;
 rule->family = message->header.family;
 rule->profile_id = input->profile_id;
 rule->flags = message->header.flags;
 rule->content = content;
 rule->directory_name = message->header.command == SKP_SEQ_ADD_DIR_NAME;
 rule->contents_only = message->header.command == SKP_SEQ_ADD_PATH_CONTENTS;
 if (content)
  susfs_content_get(content);
 rule->selector = skp_selector_get(&input->subjects);
 if (!rule->selector) {
  if (content)
   susfs_content_put(content);
  kvfree(rule);
  return -ENOMEM;
 }
 memcpy(rule->path, input->path, sizeof(rule->path));
 memcpy(rule->target, input->target, sizeof(rule->target));
 rule->values = input->values;
 if (rule->contents_only && !sus_path_contents_supported()) {
  skp_rule_free(rule);
  return -EOPNOTSUPP;
 }
 WRITE_ONCE(resolving_task, current);
 result = rule->directory_name ?
  (susfs_directory_names_ready() && sus_path_name_supported() ? 0 : -EOPNOTSUPP) :
  skp_resolve(rule);
 WRITE_ONCE(resolving_task, NULL);
 if (result == -ENOENT && rule->family == SKP_SEQ_PATH &&
     (rule->flags & SKP_SEQ_ALLOW_PENDING)) {
  rule->pending_cred = get_current_cred();
  result = 0;
 }
 if (!result)
  result = content ? (susfs_content_ready() ? 0 : -EOPNOTSUPP) :
   skp_prepare_route(rule->family);
 if (result) {
  skp_rule_free(rule);
  return result;
 }
 list_for_each_entry(item, rules[rule->family], list)
  if (item->selector == rule->selector && item->profile_id == rule->profile_id &&
      item->directory_name == rule->directory_name &&
      !strcmp(item->path, rule->path)) {
   previous = item;
   break;
  }
 if (!previous && counts[rule->family] >= capacities[rule->family]) {
  skp_rule_free(rule);
  return -ENOSPC;
 }
 if (previous) {
  if (previous->contents_only != rule->contents_only)
   WRITE_ONCE(path_contents_count, path_contents_count + (rule->contents_only ? 1 : -1));
  list_replace_rcu(&previous->list, &rule->list);
  synchronize_rcu();
  skp_rule_free(previous);
 } else {
  list_add_tail_rcu(&rule->list, rules[rule->family]);
  WRITE_ONCE(counts[rule->family], counts[rule->family] + 1);
  if (rule->directory_name)
   WRITE_ONCE(directory_name_count, directory_name_count + 1);
  if (rule->contents_only)
   WRITE_ONCE(path_contents_count, path_contents_count + 1);
 }
 if (rule->pending_cred) {
  pending_passes = 0;
  pending_cycle++;
  schedule_delayed_work(&pending_work, 2 * HZ);
 }
 return 0;
}
static void skp_clear(u32 family)
{
 LIST_HEAD(retired);
 struct skp_rule *rule, *next;
 list_for_each_entry_safe(rule, next, rules[family], list) {
  list_del_rcu(&rule->list);
  list_add_tail(&rule->retired, &retired);
 }
 WRITE_ONCE(counts[family], 0);
 if (family == SKP_SEQ_PATH) {
  WRITE_ONCE(directory_name_count, 0);
  WRITE_ONCE(path_contents_count, 0);
 }
 synchronize_rcu();
 list_for_each_entry_safe(rule, next, &retired, retired) {
  list_del(&rule->retired);
  skp_rule_free(rule);
 }
}
void skp_policy_release_superblock(struct super_block *sb)
{
 LIST_HEAD(retired);
 struct skp_rule *rule, *next;
 unsigned int family;
 mutex_lock(&policy_write_lock);
 for (family = SKP_SEQ_PATH; family <= SKP_SEQ_REDIRECT; family++) {
  if (family != SKP_SEQ_PATH && family != SKP_SEQ_REDIRECT)
   continue;
  list_for_each_entry_safe(rule, next, rules[family], list) {
   if (!rule->inode || rule->inode->i_sb != sb)
    continue;
   list_del_rcu(&rule->list);
   list_add_tail(&rule->retired, &retired);
   WRITE_ONCE(counts[family], counts[family] - 1);
   if (rule->contents_only)
    WRITE_ONCE(path_contents_count, path_contents_count - 1);
  }
 }
 synchronize_rcu();
 list_for_each_entry_safe(rule, next, &retired, retired) {
  list_del(&rule->retired);
  skp_rule_free(rule);
 }
 mutex_unlock(&policy_write_lock);
}
static void skp_pending_work(struct work_struct *work)
{
 struct skp_rule *rule, *next;
 unsigned int tried = 0;
 bool pending = false, budget_exhausted = false;
 if (!mutex_trylock(&policy_write_lock)) {
  if (!READ_ONCE(stopping))
   schedule_delayed_work(&pending_work, 2 * HZ);
  return;
 }
 if (stopping)
  goto out;
 list_for_each_entry_safe(rule, next, &path_rules, list) {
  struct skp_rule *resolved;
  const struct cred *saved;
  int result;
  if (!rule->pending_cred)
   continue;
  pending = true;
  if (rule->pending_attempt == pending_cycle)
   continue;
  if (tried++ >= 128) {
   budget_exhausted = true;
   break;
  }
  rule->pending_attempt = pending_cycle;
  resolved = kvzalloc(sizeof(*resolved), GFP_KERNEL);
  if (!resolved)
   break;
  *resolved = *rule;
  saved = override_creds(rule->pending_cred);
  WRITE_ONCE(resolving_task, current);
  result = skp_resolve(resolved);
  WRITE_ONCE(resolving_task, NULL);
  revert_creds(saved);
  if (result) {
   /* The selector and credential still belong to the old pending rule. */
   resolved->selector = NULL;
   resolved->pending_cred = NULL;
   skp_rule_free(resolved);
   continue;
  }
  resolved->pending_cred = NULL;
  resolved->list.next = &resolved->list;
  resolved->list.prev = &resolved->list;
  resolved->retired.next = &resolved->retired;
  resolved->retired.prev = &resolved->retired;
  list_replace_rcu(&rule->list, &resolved->list);
  synchronize_rcu();
  rule->selector = NULL; /* transfer the one reference */
  skp_rule_free(rule);
 }
 if (!budget_exhausted) {
  pending_passes++;
  pending_cycle++;
 }
 if (pending && pending_passes <= 60)
  schedule_delayed_work(&pending_work, 2 * HZ);
out:
 mutex_unlock(&policy_write_lock);
}
static int skp_policy_show(struct seq_file *stream, void *unused)
{
 unsigned int regular;
 char dirent[768];
 if (current_uid().val != 0)
  return -EACCES;
 mutex_lock(&policy_write_lock);
 regular = susfs_content_regular_filesystems();
 susfs_dirent_status_json(dirent, sizeof(dirent));
 seq_printf(stream, "{\"backend\":\"lkm\",\"sequential_abi\":%u,\"message_bytes\":%zu,"
  "\"path_count\":%u,\"kstat_count\":%u,\"map_count\":%u,\"redirect_count\":%u,\"mount_count\":%u,"
  "\"precise_manager_sessions\":true,\"mount_scope\":\"prefix\",\"mount_unique_id\":false,"
  "\"path_contents_hide\":%s,\"path_contents_count\":%u,\"path_contents_mode\":\"directory_search\",\"path_contents_disabled_reason\":\"%s\","
  "\"directory_name_hide\":%s,\"directory_name_match\":\"exact\",\"directory_name_count\":%u,"
  "\"content_redirect\":%s,\"content_disabled_reason\":\"%s\",\"content_sources\":[\"/proc/cpuinfo\",\"/proc/meminfo\",\"/proc/version\","
  "\"/proc/uptime\",\"/proc/loadavg\",\"/proc/stat\",\"/proc/cmdline\",\"/proc/bootconfig\"],"
  "\"content_max_bytes\":1048576,\"content_limit_bytes\":8388608,\"content_bytes\":%lu,"
  "\"content_regular_files\":%s,\"content_regular_filesystems\":[%s%s%s%s],\"dirent\":%s}\n",
  SKP_SEQUENTIAL_VERSION, sizeof(struct skp_sequential_message), counts[1], counts[2],
  counts[3], counts[4], counts[5],
  sus_path_contents_supported() ? "true" : "false",
  path_contents_count, sus_path_contents_disabled_reason(),
  susfs_directory_names_ready() && sus_path_name_supported() ? "true" : "false",
  directory_name_count, susfs_content_ready() ? "true" : "false", susfs_content_disabled_reason(),
  susfs_content_bytes(), regular ? "true" : "false",
  (regular & SUSFS_CONTENT_FS_EXT4) ? "\"ext4\"" : "",
  (regular & SUSFS_CONTENT_FS_F2FS) ?
   ((regular & SUSFS_CONTENT_FS_EXT4) ? ",\"f2fs\"" : "\"f2fs\"") : "",
  (regular & SUSFS_CONTENT_FS_TMPFS) ?
   ((regular & (SUSFS_CONTENT_FS_EXT4 | SUSFS_CONTENT_FS_F2FS)) ? ",\"tmpfs\"" : "\"tmpfs\"") : "",
  (regular & SUSFS_CONTENT_FS_EROFS) ?
   ((regular & (SUSFS_CONTENT_FS_EXT4 | SUSFS_CONTENT_FS_F2FS | SUSFS_CONTENT_FS_TMPFS)) ? ",\"erofs\"" : "\"erofs\"") : "", dirent);
 mutex_unlock(&policy_write_lock);
 return 0;
}
static int skp_policy_open(struct inode *inode, struct file *file)
{
 struct skp_policy_session *session;
 int result;
 if (current_uid().val != 0)
  return -EACCES;
 session = kzalloc(sizeof(*session), GFP_KERNEL);
 if (!session)
  return -ENOMEM;
 session->leader = current->group_leader;
 get_task_struct(session->leader);
 result = single_open(file, skp_policy_show, session);
 if (result) {
  put_task_struct(session->leader);
  kfree(session);
 }
 return result;
}
static int skp_policy_release(struct inode *inode, struct file *file)
{
 struct seq_file *stream = file->private_data;
 struct skp_policy_session *session = stream->private;
 mutex_lock(&policy_write_lock);
 if (session->registered) {
  list_del_rcu(&session->list);
  synchronize_rcu();
 }
 mutex_unlock(&policy_write_lock);
 put_task_struct(session->leader);
 kfree(session);
 return single_release(inode, file);
}
static ssize_t skp_policy_read(struct file *file, char __user *buffer,
 size_t size, loff_t *position)
{
 return current_uid().val == 0 ? seq_read(file, buffer, size, position) : -EACCES;
}
static ssize_t skp_policy_write(struct file *file, const char __user *buffer,
 size_t size, loff_t *position)
{
 struct skp_sequential_header *header;
 struct susfs_content *content = NULL;
 struct skp_policy_session *session = ((struct seq_file *)file->private_data)->private;
 int result = 0;
 if (current_uid().val != 0)
  return -EACCES;
 if (size != sizeof(*header) && size != sizeof(struct skp_sequential_message))
  return -EMSGSIZE;
 header = memdup_user(buffer, size);
 if (IS_ERR(header))
  return PTR_ERR(header);
 if (header->magic != SKP_SEQUENTIAL_MAGIC || header->version != SKP_SEQUENTIAL_VERSION ||
     header->size != size) {
  result = -EINVAL;
  goto free;
 }
 /* Payload preparation must happen before the policy mutex: opening/reading
  * B can invoke filesystem callbacks. The immutable payload is published only
  * after the ordinary add validation/selector work under the existing lock. */
 if (header->command == SKP_SEQ_ADD_CONTENT) {
  const struct skp_sequential_message *message = (const void *)header;
  if (size != sizeof(*message) || header->family != SKP_SEQ_REDIRECT || header->flags) {
   result = -EINVAL;
   goto free;
  }
  result = skp_validate_add(message);
  if (!result && !susfs_content_ready())
   result = -EOPNOTSUPP;
  if (!result)
   result = susfs_content_prepare(message->rule.path, message->rule.target, &content);
  if (result)
   goto free;
 }
 if (!mutex_trylock(&policy_write_lock)) {
  result = -EBUSY;
  goto free;
 }
 if (stopping) {
  result = -ESHUTDOWN;
  goto out;
 }
 if (header->command == SKP_SEQ_REGISTER_MANAGER) {
  if (size != sizeof(*header) || header->family || header->flags ||
      session->leader != current->group_leader) {
   result = -EINVAL;
   goto out;
  }
  if (!session->registered) {
   list_add_tail_rcu(&session->list, &manager_sessions);
   session->registered = true;
  }
 } else if (!header->family || header->family > SKP_SEQ_FAMILY_COUNT ||
     (header->flags & ~SKP_SEQ_ALLOW_PENDING) ||
     (header->flags && header->family != SKP_SEQ_PATH)) {
  result = -EINVAL;
 } else if (header->command == SKP_SEQ_CLEAR_FAMILY && size == sizeof(*header) && !header->flags) {
  skp_clear(header->family);
 } else if ((header->command == SKP_SEQ_ADD_RULE || header->command == SKP_SEQ_ADD_CONTENT ||
             header->command == SKP_SEQ_ADD_DIR_NAME || header->command == SKP_SEQ_ADD_PATH_CONTENTS) &&
     size == sizeof(struct skp_sequential_message)) {
  result = skp_add((struct skp_sequential_message *)header, content);
 } else result = -EINVAL;
out:
 mutex_unlock(&policy_write_lock);
free:
 if (content)
  susfs_content_put(content);
 kfree(header);
 return result ? result : size;
}
static const struct proc_ops skp_policy_ops = {
 .proc_open = skp_policy_open, .proc_read = skp_policy_read,
 .proc_write = skp_policy_write, .proc_lseek = seq_lseek, .proc_release = skp_policy_release,
};
int skp_policy_adapter_init(void)
{
 WRITE_ONCE(stopping, false);
 susfs_directory_names_init();
 if (!susfs_control_node_allowed())
  return 0;
 policy_node = proc_create(SKP_POLICY_NODE_NAME, 0777, NULL, &skp_policy_ops);
 return policy_node ? 0 : -ENOMEM;
}
void skp_policy_adapter_exit(void)
{
 unsigned int family;
 mutex_lock(&policy_write_lock);
 WRITE_ONCE(stopping, true);
 mutex_unlock(&policy_write_lock);
 if (policy_node) {
  proc_remove(policy_node);
  policy_node = NULL;
 }
 cancel_delayed_work_sync(&pending_work);
 mutex_lock(&policy_write_lock);
 for (family = SKP_SEQ_PATH; family <= SKP_SEQ_MOUNT; family++)
  skp_clear(family);
 mutex_unlock(&policy_write_lock);
 /* All rule readers and proc releases have drained. Route callbacks are
  * subsequently removed by their owning feature's normal exit routine. */
 synchronize_rcu();
}
