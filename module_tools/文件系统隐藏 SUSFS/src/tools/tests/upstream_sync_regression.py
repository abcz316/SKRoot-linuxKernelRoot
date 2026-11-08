#!/usr/bin/env python3
"""Exercise actual upstream-sync functions with bounded host lifecycle doubles."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from path_hook_regression import execute, execution_path


def function(source, name, structure=False):
    masked = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    signature = rf'^struct\s+{name}\s*\{{' if structure else (
        rf'^(?:static\s+)?(?:(?:__nocfi|noinline)\s+)*(?:int|void|bool)\s+{name}\s*\([^;{{}}]*\)\s*\{{')
    matches = list(re.finditer(signature, masked, re.M))
    if len(matches) != 1:
        raise ValueError((name, len(matches)))
    start = matches[0].start()
    depth = 0
    for i in range(masked.index('{', start), len(masked)):
        depth += (masked[i] == '{') - (masked[i] == '}')
        if not depth:
            return source[start:i+1+int(structure)] + '\n'
    raise ValueError(name)


COMMON = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#define __nocfi
#define noinline __attribute__((noinline))
#define __user
#define GFP_KERNEL 0
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_ACQUIRE)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),(v),__ATOMIC_RELEASE)
static void discard_log(const char *format,...) {(void)format;}
#define SUSFS_LOGI discard_log
#define pr_warn discard_log
#define pr_err discard_log
#define pr_warn_ratelimited discard_log
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) assert(pthread_mutex_lock(p)==0)
#define mutex_unlock(p) assert(pthread_mutex_unlock(p)==0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static atomic_uint checks;
static void expect(bool ok,const char *why) { checks++;if(!ok){fprintf(stderr,"FAIL %s\n",why);abort();} }
'''
BOOT = r'''
static char original[]="original boot text",param_bootconfig[4096];
static char *saved_boot_config=original,*orig_boot_config,*fake_boot_config;
static bool spoof_active,symbol_available=true;
static atomic_uint allocations,wait_calls;
static atomic_bool allocation_fail,wait_entered,writer_done,exit_done;
static pthread_mutex_t reader_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reader_event=PTHREAD_COND_INITIALIZER;
static char *held_pointer;
static bool reader_holds;
static void mock_grace_period(void) {
 atomic_fetch_add(&wait_calls,1);
 mutex_lock(&reader_lock);atomic_store(&wait_entered,true);pthread_cond_broadcast(&reader_event);
 while(reader_holds)pthread_cond_wait(&reader_event,&reader_lock);
 mutex_unlock(&reader_lock);
}
static void *find_kernel_symbol_exact(const char *name) {
 expect(!strcmp(name,"synchronize_rcu_tasks"),"only real Tasks grace period resolved");
 return symbol_available?(void*)mock_grace_period:NULL;
}
static char *kstrdup(const char *s,int flags) {
 (void)flags;if(atomic_exchange(&allocation_fail,false))return NULL;
 char *p=strdup(s);assert(p);atomic_fetch_add(&allocations,1);return p;
}
static void kfree(void *p) {
 if(!p)return;
 mutex_lock(&reader_lock);expect(!reader_holds||p!=held_pointer,"live reader buffer not freed");mutex_unlock(&reader_lock);
 expect(atomic_fetch_sub(&allocations,1)>0,"allocation balance");free(p);
}
'''
BOOT_TEST = r'''
static void fresh(bool available) {
 expect(atomic_load(&allocations)==0,"prior run fully released");
 saved_boot_config=original;orig_boot_config=fake_boot_config=NULL;spoof_active=spoof_exiting=false;
 memset(param_bootconfig,0,sizeof(param_bootconfig));symbol_available=available;
 atomic_store(&wait_entered,false);atomic_store(&writer_done,false);atomic_store(&exit_done,false);
 reader_holds=false;held_pointer=NULL;
}
static void *writer(void *p) {int rc=spoof_set((char*)p);expect(rc==0,"writer publishes");atomic_store(&writer_done,true);return NULL;}
static void *exiter(void *unused) {(void)unused;susfs_spoof_cmdline_exit();atomic_store(&exit_done,true);return NULL;}
static void *repeat_writer(void *p) {
 char text[64];for(unsigned i=0;i<100;i++){snprintf(text,sizeof(text),"thread %ld write %u",(long)p,i);expect(spoof_set(text)==0,"concurrent write succeeds");}
 return NULL;
}
int main(void) {
 fresh(false);expect(susfs_spoof_cmdline_init()==0,"missing primitive with empty config keeps other features");
 expect(spoof_set("unavailable")==-EOPNOTSUPP&&saved_boot_config==original&&!atomic_load(&allocations),"missing primitive fails before publication");
 strcpy(param_bootconfig,"configured");expect(susfs_spoof_cmdline_init()==-EOPNOTSUPP,"missing primitive refuses configured startup");
 susfs_spoof_cmdline_exit();expect(!atomic_load(&allocations),"unarmed exit safe");
 fresh(true);expect(susfs_spoof_cmdline_init()==0,"resolve grace period");
 expect(spoof_set("first")==0&&orig_boot_config==original,"first set saves original");
 atomic_store(&allocation_fail,true);char *previous=saved_boot_config;
 expect(spoof_set("fail")==-ENOMEM&&saved_boot_config==previous,"failed allocation leaves live string untouched");
 for(unsigned i=0;i<500;i++){expect(spoof_set("short")==0,"repeated update");expect(atomic_load(&allocations)==1,"one live allocation after each update");}
 pthread_t workers[2];expect(!pthread_create(&workers[0],NULL,repeat_writer,(void*)1),"spawn writer1");
 expect(!pthread_create(&workers[1],NULL,repeat_writer,(void*)2),"spawn writer2");
 pthread_join(workers[0],NULL);pthread_join(workers[1],NULL);
 expect(orig_boot_config==original&&atomic_load(&allocations)==1,"concurrent writes preserve original and reclaim old");
 mutex_lock(&reader_lock);held_pointer=saved_boot_config;reader_holds=true;atomic_store(&wait_entered,false);mutex_unlock(&reader_lock);
 pthread_t update,stop;expect(!pthread_create(&update,NULL,writer,"new live string"),"spawn blocked update");
 mutex_lock(&reader_lock);while(!atomic_load(&wait_entered))pthread_cond_wait(&reader_event,&reader_lock);
 expect(!atomic_load(&writer_done)&&atomic_load(&allocations)==2,"publisher waits while reader retains old buffer");
 mutex_unlock(&reader_lock);
 expect(!pthread_create(&stop,NULL,exiter,NULL),"spawn stop");
 mutex_lock(&reader_lock);expect(!atomic_load(&exit_done),"stop serializes with publisher");
 reader_holds=false;pthread_cond_broadcast(&reader_event);mutex_unlock(&reader_lock);
 pthread_join(update,NULL);pthread_join(stop,NULL);
 expect(saved_boot_config==original&&!atomic_load(&allocations),"exit restores original and releases every buffer");
 expect(spoof_set("too late")==-ESHUTDOWN&&!atomic_load(&allocations),"late update refused");
 susfs_spoof_cmdline_exit();expect(saved_boot_config==original&&!atomic_load(&allocations),"exit idempotent");
 printf("PASS bootconfig checks=%u\n",checks);return 0;
}
'''
UNAME = r'''
#define SUSFS_UNAME_LEN 65
struct new_utsname {char release[65],version[65];};
struct st_susfs_uname {char release[65],version[65];int err;};
struct uname_args {struct new_utsname *name;};
struct kretprobe_instance {void *data;};
struct pt_regs {long result;};
static char fake_release[65],fake_version[65];
static bool uname_spoof_enabled;
static unsigned writes;
static int registration_error;
static struct new_utsname original={.release="stock",.version="stock-version"};
static struct new_utsname *utsname(void){return &original;}
static int uname_register(void){return registration_error;}
static long regs_return_value(struct pt_regs*r){return r->result;}
static unsigned long copy_from_user(void*d,const void*s,size_t n){memcpy(d,s,n);return 0;}
static unsigned long copy_to_user(void*d,const void*s,size_t n){writes++;memcpy(d,s,n);return 0;}
static bool susfs_abi_path_ok(const char*s,size_t n){return strnlen(s,n)<n;}
static long strscpy_pad(char*d,const char*s,size_t n){
 size_t len=strnlen(s,n);if(len>=n)return-E2BIG;memcpy(d,s,len+1);memset(d+len,0,n-len);return(long)len;
}
'''
UNAME_TEST = r'''
static void zero_tail(const char*s){for(size_t i=strlen(s)+1;i<65;i++)expect(!s[i],"zero bytes after terminator");}
int main(void){
 struct st_susfs_uname input={0};void*arg=&input;
 memset(input.release,'L',64);memset(input.version,'V',64);susfs_uname_supercall(&arg);expect(!input.err,"max supported field");
 strcpy(input.release,"r");strcpy(input.version,"v");susfs_uname_supercall(&arg);expect(!input.err,"short update");zero_tail(fake_release);zero_tail(fake_version);
 strcpy(input.release,"default");strcpy(input.version,"default");susfs_uname_supercall(&arg);
 expect(!strcmp(fake_release,original.release)&&!strcmp(fake_version,original.version),"default restored");zero_tail(fake_release);
 memset(fake_release,'x',65);memset(fake_version,'x',65);strcpy(fake_release,"short");strcpy(fake_version,"short");
 expect(!susfs_uname_init(),"init pads parameter buffer");zero_tail(fake_release);zero_tail(fake_version);
 memset(fake_release,'y',65);memset(fake_version,'z',65);strcpy(fake_release,"live");strcpy(fake_version,"live");
 struct new_utsname output={0};struct uname_args a={&output};struct kretprobe_instance ri={&a};struct pt_regs regs={0};
 uname_spoof_enabled=true;writes=0;expect(!kr_newuname_ret(&ri,&regs)&&writes==2,"return writes both fields");
 zero_tail(output.release);zero_tail(output.version);expect(!strcmp(output.release,"live"),"live sysfs value retained");
 writes=0;regs.result=-EFAULT;kr_newuname_ret(&ri,&regs);expect(!writes,"failed syscall untouched");
 regs.result=0;uname_spoof_enabled=false;kr_newuname_ret(&ri,&regs);expect(!writes,"disabled untouched");
 a.name=NULL;uname_spoof_enabled=true;kr_newuname_ret(&ri,&regs);expect(!writes,"null output untouched");
 memset(&input,'a',sizeof(input));susfs_uname_supercall(&arg);expect(input.err==-ENAMETOOLONG,"unterminated fields rejected");
 printf("PASS uname checks=%u\n",checks);return 0;
}
'''
MOUNT = r'''
typedef unsigned int fixture_dev;
#define dev_t fixture_dev
struct inode {unsigned long i_ino;};
struct dentry {struct inode*d_inode;};
struct super_block {dev_t s_dev;};
struct mount {const char*mnt_devname;struct{struct dentry*mnt_root;struct super_block*mnt_sb;}mnt;};
#define smp_load_acquire(p) READ_ONCE(*(p))
#define smp_store_release(p,v) WRITE_ONCE(*(p),(v))
static pthread_mutex_t ident_lock=PTHREAD_MUTEX_INITIALIZER;
#define spin_lock_irqsave(p,f) do{(f)=0;mutex_lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);mutex_unlock(p);}while(0)
#define atomic_inc(p) (++*(p))
static int n_ident=1;
static unsigned n_ident_dropped_dev;
'''
MOUNT_TEST = r'''
static atomic_bool stop_reader,reader_started;
static struct inode known_inode={10},other_inode={99};
static struct dentry known_dentry={&known_inode},other_dentry={&other_inode};
static struct super_block known_sb={11},other_sb={22};
static struct mount known={.mnt_devname="/fixture/source",.mnt={&known_dentry,&known_sb}};
static struct mount unrelated={.mnt_devname="/fixture/never",.mnt={&other_dentry,&other_sb}};
static void *identity_reader(void*unused){
 (void)unused;
 expect(!sus_mount_ident_match(&unrelated),"first concurrent identity check");
 atomic_store(&reader_started,true);
 while(!atomic_load(&stop_reader))expect(!sus_mount_ident_match(&unrelated),"concurrent slot mutation cannot manufacture unrelated name");
 return NULL;
}
int main(void){
 mount_ident[0].s_dev=11;mount_ident[0].root_ino=10;mount_ident[0].devname_is_path=true;strcpy(mount_ident[0].devname,known.mnt_devname);
 expect(sus_mount_ident_match(&known),"live identity matches");
 sus_mount_ident_drop_dev(11);expect(!mount_ident[0].root_ino&&!mount_ident[0].devname_is_path&&!mount_ident[0].devname[0],"invalidate both keys");
 unrelated.mnt_devname="/fixture/source";expect(!sus_mount_ident_match(&unrelated),"old source name no longer matches");
 strcpy(mount_ident[0].devname,"/fixture/source");mount_ident[0].devname_is_path=true;
 expect(!sus_mount_ident_match(&unrelated),"invalid slot never checks source key");
 unrelated.mnt_devname="/fixture/never";
 pthread_t thread;expect(!pthread_create(&thread,NULL,identity_reader,NULL),"reader started");
 while(!atomic_load(&reader_started))sched_yield();
 for(unsigned i=0;i<2000;i++){
  unsigned long flags;spin_lock_irqsave(&ident_lock,flags);
  mount_ident[0].s_dev=11;strcpy(mount_ident[0].devname,"/fixture/source");
  mount_ident[0].devname_is_path=true;mount_ident[0].root_ino=10;spin_unlock_irqrestore(&ident_lock,flags);
  sus_mount_ident_drop_dev(11);
 }
 atomic_store(&stop_reader,true);pthread_join(thread,NULL);
 printf("PASS mount-identity checks=%u\n",checks);return 0;
}
'''
SCAN = r'''
typedef unsigned int fixture_dev;
#define dev_t fixture_dev
#define KERNEL_VERSION(a,b,c) (((a)<<16)+((b)<<8)+(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,12,0)
#define SUS_MOUNT_MAX_SCAN 65536
#define SUS_MOUNT_KSU_ID_MIN 2000000000U
#define DEFAULT_KSU_MNT_ID 2000000000ULL
#define SUS_MOUNT_MIN_SANE_MNT_ID 1000000
#define PATH_MAX 4096
struct inode {unsigned long i_ino;};
struct dentry {struct inode*d_inode;};
struct super_block {dev_t s_dev;};
struct vfsmount {struct dentry*mnt_root;struct super_block*mnt_sb;};
struct mount {int mnt_id;const char*mnt_devname;struct vfsmount mnt;};
struct mnt_namespace {unsigned count;struct mount items[160];};
struct path {struct vfsmount*mnt;struct dentry*dentry;};
struct nsproxy {struct mnt_namespace*mnt_ns;};
static struct mnt_namespace ns;
static struct nsproxy proxy={&ns};
static struct {struct nsproxy*nsproxy;} task={&proxy},*current=&task;
static struct inode inode;
static struct dentry dentry={&inode};
static struct super_block sb={10};
static unsigned long param_min_mnt_id=SUS_MOUNT_KSU_ID_MIN;
static int n_ident;
static unsigned pass_calls,next_id,allocs,releases,old_releases,mappings,identity_adds;
static int fail_pass;
static bool allocator_ready=true,namespace_locked,read_locked,fail_allocation;
static int sus_mount_mnt_id_ida=1,pfn_ida_alloc_range=1,pfn_ida_free=1;
static bool allocated[1400];
#define SUS_MOUNT_ITER_TYPE unsigned int
#define SUS_MOUNT_ITER_FOR(n,p) for((p)=0;(p)<(n)->count;(p)++)
#define SUS_MOUNT_ITER_MOUNT(p) (&ns->items[p])
#define SUS_MOUNT_MNT_NOT_IN_NS(r,n) false
#define IS_ERR_OR_NULL(p) (!(p))
static bool sus_mount_ida_ready(void){return allocator_ready;}
static bool sus_mount_ns_walk_begin(void){
 expect(!namespace_locked,"namespace lock not recursive");pass_calls++;
 if(fail_pass>0&&pass_calls==(unsigned)fail_pass)return false;
 namespace_locked=true;return true;
}
static void sus_mount_ns_walk_end(void){expect(namespace_locked&&!read_locked,"namespace unlock after RCU");namespace_locked=false;}
static void rcu_read_lock(void){expect(namespace_locked&&!read_locked,"RCU acquired after namespace lock");read_locked=true;}
static void rcu_read_unlock(void){expect(read_locked,"RCU balanced");read_locked=false;}
static int sus_mount_ida_alloc(void){
 expect(namespace_locked&&!read_locked,"ID allocation before RCU traversal");
 if(fail_allocation)return-ENOMEM;
 expect(next_id<ARRAY_SIZE(allocated),"fixture ID capacity");allocated[next_id]=true;allocs++;
 return (int)(SUS_MOUNT_KSU_ID_MIN+next_id++);
}
static void sus_mount_ida_release(int id){
 expect(!read_locked,"ID release after RCU traversal");
 if((unsigned)id<SUS_MOUNT_KSU_ID_MIN){old_releases++;return;}
 unsigned index=(unsigned)id-SUS_MOUNT_KSU_ID_MIN;
 expect(index<ARRAY_SIZE(allocated)&&allocated[index],"release only allocated IDs");
 allocated[index]=false;releases++;
}
static void sus_mount_idmap_add(int id,int shown,dev_t dev){(void)id;(void)shown;(void)dev;mappings++;}
static int sus_mount_shown_id(struct mount*r){(void)r;return 1;}
static void sus_mount_ident_add(struct mount*r){(void)r;identity_adds++;}
static bool sus_mount_path_is_ours(const char*s){return s&&strstr(s,"/fixture/")==s;}
static char*sus_mount_d_path(struct path*p,char*b,int n){(void)p;(void)n;strcpy(b,"/unmatched");return b;}
static unsigned long sus_mount_min_mnt_id(void){return param_min_mnt_id;}
static void*kmalloc(size_t n,int flags){(void)flags;return malloc(n);}
static void kfree(void*p){free(p);}
'''
SCAN_TEST = r'''
static void scan_reset(unsigned count){
 memset(&ns,0,sizeof(ns));ns.count=count;memset(allocated,0,sizeof(allocated));
 pass_calls=next_id=allocs=releases=old_releases=mappings=identity_adds=0;
 fail_pass=0;allocator_ready=true;fail_allocation=false;
 for(unsigned i=0;i<count;i++)ns.items[i]=(struct mount){100+(int)i,"/fixture/mount",{&dentry,&sb}};
}
static unsigned marked_count(void){unsigned count=0;for(unsigned i=0;i<ns.count;i++)count+=(unsigned)ns.items[i].mnt_id>=SUS_MOUNT_KSU_ID_MIN;return count;}
int main(void){
 const unsigned totals[]={0,1,8,9,16,80,128,129};
 for(unsigned i=0;i<ARRAY_SIZE(totals);i++){
  scan_reset(totals[i]);int result=sus_mount_mark_ksu_mounts();unsigned expected=totals[i]>128?128:totals[i];
  expect(result==(int)expected&&marked_count()==expected,"scan continues beyond first eight within bound");
  expect(pass_calls<=SUS_MOUNT_SCAN_PASSES&&!namespace_locked&&!read_locked,"pass count and locks bounded");
  expect(allocs-releases==expected&&old_releases==expected,"new and old ID ownership balanced");
  unsigned old=old_releases;expect(sus_mount_mark_ksu_mounts()==(totals[i]>128?1:0),"repeat scan marks only remaining items");
  expect(old_releases==old+(totals[i]>128?1:0),"no double release of existing IDs");
 }
 scan_reset(9);fail_pass=2;expect(sus_mount_mark_ksu_mounts()==-ENOSYS,"later pass error propagated");
 expect(marked_count()==8&&!namespace_locked&&!read_locked,"partial effect does not leak locks");
 scan_reset(3);fail_allocation=true;expect(sus_mount_mark_ksu_mounts()==0&&!marked_count()&&!namespace_locked,"allocation failure no mutation and balanced");
 scan_reset(3);allocator_ready=false;expect(sus_mount_mark_ksu_mounts()==-ENOSYS&&!pass_calls,"missing ID allocator fails before scan");
 printf("PASS mount-scan checks=%u\n",checks);return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[2]
    boot = (repo/'kernel/spoof_cmdline.c').read_text()
    uname = (repo/'kernel/susfs_uname.c').read_text()
    mount = (repo/'kernel/sus_mount.c').read_text()
    cases = {
        'bootconfig': COMMON+BOOT+'\n'.join(function(boot,n) for n in
            ('spoof_wait_readers','spoof_set','susfs_spoof_cmdline_init','susfs_spoof_cmdline_exit')),
        'uname': COMMON+UNAME+'\n'.join(function(uname,n) for n in
            ('uname_pad','kr_newuname_ret','susfs_uname_init','susfs_uname_supercall'))+UNAME_TEST,
        'mount-identity': COMMON+MOUNT+''.join(re.findall(r'^#define SUS_MOUNT_(?:IDENT_MAX|DEVNAME_MAX) .*\n',mount,re.M))
            +function(mount,'sus_mount_ident',True)+'static struct sus_mount_ident mount_ident[SUS_MOUNT_IDENT_MAX];\n'
            +function(mount,'sus_mount_ident_match')+function(mount,'sus_mount_ident_drop_dev')+MOUNT_TEST,
        'mount-scan': COMMON+SCAN+''.join(re.findall(r'^#define SUS_MOUNT_(?:ID_BATCH|SCAN_PASSES) .*\n',mount,re.M))
            +function(mount,'sus_mount_scan_ns')+function(mount,'sus_mount_mark_ksu_mounts')+SCAN_TEST,
    }
    # Production global state is declared here so the extracted functions retain
    # their real mutex/pointer ordering without importing the whole kernel.
    cases['bootconfig'] = cases['bootconfig'].replace(
        'static __nocfi noinline void spoof_wait_readers',
        'static bool spoof_exiting;\nstatic DEFINE_MUTEX(spoof_lock);\nstatic void (*spoof_sync_readers_fn)(void);\nstatic __nocfi noinline void spoof_wait_readers',1)+BOOT_TEST
    report = {'kernel_execution':False,'runs':[],'sources':{
        p:hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in
        ('kernel/spoof_cmdline.c','kernel/susfs_uname.c','kernel/sus_mount.c','kernel/imports_guard.c')}}
    for name, source in cases.items():
        cfile=out/(name+'.c');cfile.write_text(source)
        for variant, flags in [('normal',['-O2']),('sanitized',['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
            binary=out/(name+'-'+variant)
            build=execute(['cc','-std=gnu11','-pthread','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',*flags,execution_path(cfile),'-o',execution_path(binary)])
            (out/(name+'-'+variant+'.build.txt')).write_text(build.stdout+build.stderr)
            record={'case':name,'variant':variant,'build_exit':build.returncode,'passed':False}
            if not build.returncode:
                run=execute(['env','ASAN_OPTIONS=detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS=halt_on_error=1',execution_path(binary)])
                (out/(name+'-'+variant+'.out.txt')).write_text(run.stdout+run.stderr)
                record.update(exit=run.returncode,output=run.stdout.strip(),passed=run.returncode==0 and not run.stderr)
            report['runs'].append(record)
    imports=(repo/'kernel/imports_guard.c').read_text()
    table=re.search(r'^static const struct susfs_import susfs_imports\[\] = (\{.*?^\});',imports,re.M|re.S)
    if not table:
        raise ValueError('import table missing')
    source='#define IMP(n) #n\n#define IMP_DATA(n) #n\nconst char *names[] = '+table[1]+';\n'
    cfile=out/'import-table.c';cfile.write_text(source)
    for enabled in (False,True):
        flags=['-DCONFIG_HARDENED_USERCOPY=1'] if enabled else []
        result=execute(['cc','-E','-P','-x','c',*flags,execution_path(cfile)])
        present='"__check_object_size"' in result.stdout
        report['runs'].append({'case':'hardened-usercopy','enabled':enabled,
            'exit':result.returncode,'helper_present':present,
            'passed':result.returncode==0 and present==enabled})
    report['passed']=all(r['passed'] for r in report['runs'])
    (out/'upstream-sync-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
