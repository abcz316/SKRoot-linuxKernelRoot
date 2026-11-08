#!/usr/bin/env python3
"""Host regression for contents hiding without the optional redirect/alias hooks.

Compiles actual readiness, permission and sequential-selector code. Kernel
objects and original LSM calls are typed doubles; this is not a device test.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil

from path_hook_regression import execute, execution_path
from upstream_sync_regression import function

SUPPORT = r'''
static bool shared_open_ready, directory_lookup_ready = true;
static u32 directory_routes = 1U << 3;
static char scratch;
static char *dirent_tmp = &scratch;
static struct { void *entry; } sus_path_readlink_lsm_hook, sus_path_follow_link_hook;
static bool susfs_content_file_open_ready(void) { return shared_open_ready; }
static bool susfs_dirent_file_lookup_ready(void) { return directory_lookup_ready; }
static u32 susfs_kstat_group_routes(void) { return directory_routes; }
'''
PERMISSION = r'''
#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_ACCESS 16
#define MAY_OPEN 32
#define MAY_CHDIR 64
#define MAY_NOT_BLOCK 128
static atomic_int n_enoent_perm;
#define atomic_inc(p) atomic_fetch_add(p, 1)
static int original_permission_result;
static bool sus_path_inode_hidden(struct inode *inode) {
 bool hidden = false;
 skp_policy_paths_inode_override(inode, &hidden);
 return hidden;
}
#define SUS_LSM_PASS_ORIG(hook, member, ...) return original_permission_result
'''
MAIN = r'''
int main(void) {
 owner.group_leader=&owner;app.group_leader=&app;child.group_leader=&child;as_root();
 assert(!skp_policy_adapter_init() && !skp_policy_open(NULL,&control));
 /* Same inputs on baseline and modified source: original path hooks/listing
  * available; optional shared-open/alias/new symlink hooks unavailable. */
 directory_names_ready=false;shared_open_ready=false;content_supported=false;
 fixture_inode.i_mode=S_IFDIR|0755;
 configure(SKP_SEQ_PATH,"/fixture");message.header.command=SKP_SEQ_ADD_PATH_CONTENTS;
 message.rule.target[0]=0;memset(&message.rule.values,0,sizeof(message.rule.values));
 message.rule.subjects.whitelist_count=1;message.rule.subjects.whitelist[0]=10002;
 ssize_t added=submit();
 printf("shared_open=0 alias=0 added_symlink_hooks=0 listing=1 contents_available=%d add_rc=%ld\n",
        sus_path_contents_supported(),(long)added);
 if(added<0) {
  assert(added==-EOPNOTSUPP);assert(!skp_policy_release(NULL,&control));skp_policy_adapter_exit();
  puts("BASELINE contents unavailable; original source retained");return 0;
 }
 current=&app;host_uid=10001;
 bool hidden=false;skp_policy_paths_inode_override(&fixture_inode,&hidden);assert(!hidden);
 assert(!sus_path_inode_permission(&fixture_inode,MAY_READ|MAY_OPEN));
 assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC|MAY_CHDIR));
 assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC|MAY_ACCESS));
 assert(sus_path_inode_permission(&fixture_inode,MAY_EXEC)==-ENOENT);
 assert(sus_path_inode_permission(&fixture_inode,MAY_EXEC|MAY_NOT_BLOCK)==-ENOENT);
 assert(sus_path_inode_permission(&fixture_inode,MAY_EXEC|MAY_WRITE)==-ENOENT);
 assert(skp_policy_path_contents_hidden(&fixture_dentry,true));
 original_permission_result=-EACCES;
 assert(sus_path_inode_permission(&fixture_inode,MAY_READ|MAY_OPEN)==-EACCES);
 original_permission_result=0;
 struct inode elsewhere={.i_sb=&fixture_sb,.i_ino=991,.i_mode=S_IFDIR|0755};
 assert(!sus_path_inode_permission(&elsewhere,MAY_EXEC));
 struct inode descendant={.i_sb=&fixture_sb,.i_ino=992,.i_mode=S_IFDIR|0755};
 assert(!sus_path_inode_permission(&descendant,MAY_EXEC)); /* documented old-FD boundary */
 host_uid=10002;assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC));
 host_uid=0;host_accounting_uid=10001;assert(sus_path_inode_permission(&fixture_inode,MAY_EXEC)==-ENOENT);
 host_accounting_uid=10002;assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC));
 as_root();{loff_t offset=0;struct skp_sequential_header h={SKP_SEQUENTIAL_MAGIC,1,sizeof(h),SKP_SEQ_REGISTER_MANAGER,0,0};
 assert(skp_policy_write(&control,(char*)&h,sizeof(h),&offset)==sizeof(h));}
 assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC));
 assert(!skp_policy_release(NULL,&control));assert(!skp_policy_open(NULL,&control));
 path_group_supported=false;assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC));path_group_supported=true;
#if NEW_MODE
 directory_routes=0;assert(!sus_path_contents_supported());
 assert(!strcmp(sus_path_contents_disabled_reason(),"directory_listing_unavailable"));directory_routes=1U<<3;
 directory_lookup_ready=false;assert(!sus_path_contents_supported());directory_lookup_ready=true;
 dirent_tmp=NULL;assert(!sus_path_contents_supported());dirent_tmp=&scratch;
 assert(sus_path_contents_supported());
#endif
 clear(SKP_SEQ_PATH);assert(!sus_path_inode_permission(&fixture_inode,MAY_EXEC));
 assert(!skp_policy_release(NULL,&control));skp_policy_adapter_exit();assert(!allocations);
 puts("MODIFIED A visible/openable/enterable; child search=-ENOENT; original denial, subject/root/manager exemptions and cleanup PASS");
 puts("BOUNDARY creation under A denied; preexisting descendant directory reference is not revoked");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=True)
    stage = out / 'source'
    (stage / 'kernel').mkdir(parents=True, exist_ok=True)
    (stage / 'tools/tests').mkdir(parents=True, exist_ok=True)
    for source in (root / 'kernel').iterdir():
        if source.is_file() and source.suffix in ('.c', '.h'):
            shutil.copyfile(source, stage / 'kernel' / source.name)
    for name in ('sequential_test.c', 'sequential_shim.h'):
        shutil.copyfile(root / 'tools/tests' / name, stage / 'tools/tests' / name)
    path_source = (root / 'kernel/sus_path.c').read_text(encoding='utf-8')
    new = 'skp_policy_path_contents_search_hidden(inode)' in path_source
    shim_path = stage / 'tools/tests/sequential_shim.h'
    shim = shim_path.read_text(encoding='utf-8')
    shim = re.sub(r'static bool sus_path_(?:name|contents)_supported\(void\) \{[^\n]*\}\n', '', shim)
    shim = re.sub(r'static const char \*sus_path_contents_disabled_reason\(void\) \{[^\n]*\}\n', '', shim)
    support = SUPPORT
    if new:
        reasons = re.findall(r'^const char \*sus_path_contents_disabled_reason\(void\)\n\{.*?^\}', path_source, re.M | re.S)
        if len(reasons) != 1:
            raise ValueError('missing or ambiguous production capability reason')
        support += reasons[0] + '\n'
    support += function(path_source, 'sus_path_name_supported')
    support += function(path_source, 'sus_path_contents_supported')
    shim = shim.replace('static bool directory_names_ready = true;', support + '\nstatic bool directory_names_ready = true;')
    shim_path.write_text(shim, encoding='utf-8')
    generated = stage / 'check.c'
    generated.write_text('#define main existing_suite_main\n#include "tools/tests/sequential_test.c"\n#undef main\n' +
                         PERMISSION + function(path_source, 'sus_path_inode_permission') + MAIN, encoding='utf-8')
    records = []
    for sanitized in (False, True):
        binary = out / ('check-sanitized.bin' if sanitized else 'check.bin')
        flags = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitized else ['-O2']
        command = ['cc', '-std=gnu11', '-pthread', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Wno-unused-function',
                   '-Wno-unused-variable', '-Wno-sign-compare', '-DNEW_MODE='+str(int(new)), *flags,
                   execution_path(generated), execution_path(stage/'kernel/skp_subject_policy.c'), '-o', execution_path(binary)]
        build = execute(command)
        record = dict(sanitized=sanitized, build_command=command, build_exit=build.returncode,
                      build_stdout=build.stdout, build_stderr=build.stderr)
        if not build.returncode:
            run_command = ['env', 'ASAN_OPTIONS=detect_leaks=1:abort_on_error=1', 'UBSAN_OPTIONS=halt_on_error=1', execution_path(binary)]
            run = execute(run_command)
            record.update(run_command=run_command, run_exit=run.returncode, stdout=run.stdout, stderr=run.stderr)
            print(run.stdout, end='')
        else:
            print(build.stderr, end='')
        records.append(record)
    (out/'receipt.json').write_text(json.dumps(dict(source_root=str(root), kernel_execution=False,
        source_sha256={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in
                       ['kernel/sus_path.c','kernel/skp_policy_adapter.c']}, runs=records), indent=2)+'\n', encoding='utf-8')
    return 0 if all(r.get('run_exit') == 0 and not r.get('stderr') for r in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
