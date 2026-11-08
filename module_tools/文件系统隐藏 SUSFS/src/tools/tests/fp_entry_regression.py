#!/usr/bin/env python3
"""Run actual syscall-entry admission and publication with typed host doubles."""
from pathlib import Path
import argparse
import hashlib
import json
import re

from path_hook_regression import execute, execution_path
from upstream_sync_regression import function

PREAMBLE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define __NR_syscalls 512
#define SUSFS_FP_COMPAT_MAX_NR 512
#define KSU_PATCH_TEXT_FLUSH_DCACHE 1
#define smp_wmb() ((void)0)
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
'''
DOUBLES = r'''
static susfs_syscall_fn_t slots[512],compat_slots[512];
static susfs_syscall_fn_t *sys_call_table_ptr=slots,*compat_sys_call_table_ptr=compat_slots;
static unsigned writes,checks;
static bool drop_write,fail_compat;
static int write_error;
static int susfs_fp_init(void) { return 0; }
static int ksu_patch_text(void *to,const void *from,size_t n,int flags) {
 assert(n==sizeof(susfs_syscall_fn_t)&&flags==1);writes++;
 if(write_error)return write_error;
 if(fail_compat && to==&compat_slots[217])return -EIO;
 if(!drop_write)memcpy(to,from,n);
 return 0;
}
'''
MAIN = r'''
static void check_code(const u32 *code,const char *name,bool accepted,bool compat) {
 susfs_syscall_fn_t original=(susfs_syscall_fn_t)(uintptr_t)0x1000;
 susfs_syscall_fn_t old_compat=(susfs_syscall_fn_t)(uintptr_t)0x2000,saved=NULL,saved_compat=NULL;
 slots[61]=original;compat_slots[217]=old_compat;writes=0;
 struct susfs_fp_hook h={.nr=61,.nr_compat=compat?217:0,.name=name,
  .wrapper=(susfs_syscall_fn_t)code,.orig_slot=&saved,.orig_slot_compat=&saved_compat};
 int rc=susfs_fp_install(&h);checks++;
 assert(rc==(accepted?0:-EINVAL));assert(h.installed==accepted);
 if(accepted) {
  assert(slots[61]==h.wrapper&&saved==original&&writes==(compat?2U:1U));
  if(compat)assert(compat_slots[217]==h.wrapper&&saved_compat==old_compat);
 } else assert(!saved&&!saved_compat&&!writes&&slots[61]==original&&compat_slots[217]==old_compat);
}
int main(void) {
 const u32 pac[]={0xd503233f},pac_b[]={0xd503237f},bti[]={0xd503245f},bti_jc[]={0xd50324df};
 const u32 scs[]={0xf800865e},branch[]={0x14000001},nop[]={0xd503201f},wrong_scs[]={0xf800865d};
 const u32 guarded[]={0x90000008,0xf9400101,0xb4000041,0xf800865e};
 const u32 guarded_pac[]={0x90000008,0xf9400101,0xb4000041,0xd503233f};
 check_code(pac,"opath/openat",true,false);check_code(pac_b,"opath/openat",true,false);
 check_code(bti,"opath/openat",true,false);check_code(bti_jc,"opath/openat",true,false);
 check_code(scs,"opath/openat",EXPECT_SCS,true);
 check_code(guarded,"kstat/getdents64",EXPECT_SCS,true);
 check_code(guarded,"other",false,false);
 check_code(guarded_pac,"kstat/getdents64",true,true);
 check_code(branch,"opath/openat",false,false);check_code(nop,"opath/openat",false,false);
 check_code(wrong_scs,"opath/openat",false,false);
 check_code(NULL,"opath/openat",false,false);
 for(unsigned i=0;i<4;i++) {
  u32 bad[4];memcpy(bad,guarded_pac,sizeof(bad));
  bad[i]=(const u32[]){0x90000009,0xf9400121,0x34000041,0x14000001}[i];
  check_code(bad,"kstat/getdents64",false,false);
 }
#if UPDATED
 assert(!susfs_fp_has_callable_entry(NULL));
#endif
 /* Existing publication failures must still fail and keep original entries. */
 susfs_syscall_fn_t original=(susfs_syscall_fn_t)(uintptr_t)0x1000;
 struct susfs_fp_hook h={.nr=61,.nr_compat=0,.name="opath/openat",.wrapper=(susfs_syscall_fn_t)pac};
 slots[61]=original;writes=0;write_error=-EFAULT;
 assert(susfs_fp_install(&h)==-EFAULT&&!h.installed&&slots[61]==original);write_error=0;checks++;
 drop_write=true;writes=0;assert(susfs_fp_install(&h)==-EIO&&!h.installed&&slots[61]==original);drop_write=false;checks++;
 h.nr_compat=217;compat_slots[217]=original;fail_compat=true;
 assert(susfs_fp_install(&h)==-EIO&&!h.installed&&slots[61]==original&&compat_slots[217]==original);checks++;
 printf("FP_ENTRY checks=%u scs=%d PAC/BTI=accepted malformed=denied write-failures=preserved\n",checks,EXPECT_SCS);
 /* One stable before/after observation using the same SCS getdents input. */
 fail_compat=false;h=(struct susfs_fp_hook){.nr=61,.name="kstat/getdents64",.wrapper=(susfs_syscall_fn_t)guarded};
 slots[61]=original;writes=0;int rc=susfs_fp_install(&h);
 printf("OBSERVED guarded_SCS rc=%d installed=%d table_writes=%u\n",rc,h.installed,writes);
 return 0;
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    root=args.source_root.resolve();out=args.evidence.resolve();out.mkdir(parents=True,exist_ok=True)
    source=(root/'kernel/susfs_fp_hook.c').read_text(encoding='utf-8')
    header=(root/'kernel/susfs_fp_hook.h').read_text(encoding='utf-8')
    updated='bool susfs_fp_has_callable_entry(' in source
    declarations=header[header.index('struct pt_regs;'):header.index('/* Resolves and caches')]
    constants='\n'.join(re.findall(r'^#define SUSFS_ARM64_.*$',source,re.M))
    pieces=[function(source,'fp_compat_nr')]
    if updated:pieces.append(function(source,'fp_is_scs_entry'))
    pieces.extend(function(source,n) for n in [
        'susfs_fp_has_callable_entry' if updated else 'fp_has_landing_pad',
        'fp_has_getdents_guarded_entry','fp_patch_entry','susfs_fp_install'])
    generated=out/'check.c';generated.write_text(PREAMBLE+declarations+constants+'\n'+DOUBLES+''.join(pieces)+MAIN,encoding='utf-8')
    records=[]
    for shadow,bti in [(0,0),(1,0),(1,1),(0,1)]:
        for sanitized in (False,True):
            name=f'shadow{shadow}-bti{bti}'+('-asan' if sanitized else '')
            binary=out/name
            flags=['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitized else ['-O2']
            cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',*flags,
                 '-DUPDATED='+str(int(updated)),'-DEXPECT_SCS='+str(int(updated and shadow and not bti))]
            if shadow:cmd+=['-DCONFIG_SHADOW_CALL_STACK=1']
            if bti:cmd+=['-DCONFIG_ARM64_BTI_KERNEL=1']
            cmd+=[execution_path(generated),'-o',execution_path(binary)]
            build=execute(cmd)
            rec=dict(shadow=shadow,bti=bti,sanitized=sanitized,build_command=cmd,
                     build_exit=build.returncode,build_stdout=build.stdout,build_stderr=build.stderr)
            if build.returncode==0:
                command=[execution_path(binary)];run=execute(command)
                rec.update(run_command=command,run_exit=run.returncode,stdout=run.stdout,stderr=run.stderr)
                print(name,run.stdout.strip())
            else:print(build.stderr)
            records.append(rec)
    result=dict(source_root=str(root),updated=updated,device_execution=False,
                source_sha256=hashlib.sha256((root/'kernel/susfs_fp_hook.c').read_bytes()).hexdigest(),runs=records)
    (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return 0 if all(r.get('run_exit')==0 and not r.get('stderr') for r in records) else 1

if __name__=='__main__':raise SystemExit(main())
