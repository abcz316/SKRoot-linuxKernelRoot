#include <unistd.h>
#include <sys/stat.h>
#include <set>

#include "file_utils.h"
#include "kernel_struct_path_helper.h"
#include "patch_filldir64.h"
#include "patch_compat_filldir.h"
#include "patch_inode_operations_getattr.h"
#include "kernel_module_kit_umbrella.h"

#define DATA_LOCAL_TMP_DIR "/data/local/tmp"
#define DATA_LOCAL_TRACES_DIR "/data/local/traces"
#define DATA_DATA_DIR "/data/data"
#define SAFE_INODE_RANGE 1000

// 定义目标属性
#define TARGET_TMP_MODE 0771
#define TARGET_TMP_UID 2000 // shell
#define TARGET_TMP_GID 2000 // shell
#define TARGET_TMP_SELINUX_CTX "u:object_r:shell_data_file:s0"

/*
AOSP 代码标准的顺延逻辑
mkdir /data/local 0751 root root
mkdir /data/local/tmp 0771 shell shell
mkdir /data/local/traces 0771 shell shell <--- 以这里inode为靶，inode值减去1，即是/data/local/tmp的inode值
mkdir /data/data 0771 system system # <--- 以这里inode为靶，inode值减去2，即是/data/local/tmp的inode值
mkdir /data/app-private 0771 system system
mkdir /data/app-ephemeral 0771 system system
*/
static KModErr patch_filldir64(uint64_t old_ino, uint64_t new_ino) {
    kernel_module::SymbolHit filldir64;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("filldir64", kernel_module::SymbolMatchMode::Prefix, filldir64));
    printf("%s, addr: %p\n", filldir64.name, (void*)filldir64.addr);
    PatchBase patchBase;
    PatchFilldir64 patchFilldir64(patchBase, filldir64.addr);
    KModErr err = patchFilldir64.patch_filldir64(old_ino, new_ino);
    printf("patch filldir64 ret: %s\n", to_string(err).c_str());
    return err;
}

static KModErr patch_compat_filldir(uint64_t old_ino, uint64_t new_ino) {
    kernel_module::SymbolHit compat_filldir;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("compat_filldir", kernel_module::SymbolMatchMode::Prefix, compat_filldir));
    printf("%s, addr: %p\n", compat_filldir.name, (void*)compat_filldir.addr);
    PatchBase patchBase;
    PatchCompatFilldir patchCompatFilldir(patchBase, compat_filldir.addr);
    KModErr err = patchCompatFilldir.patch_compat_filldir(old_ino, new_ino);
    printf("patch compat_filldir ret: %s\n", to_string(err).c_str());
    return err;
}

static KModErr patch_inode_op_getattr(uint64_t old_ino, uint64_t new_ino) {
    scoped_kpath kpath;
    RETURN_IF_ERROR(acquire_kpath("/data/local", kpath));

    uint32_t d_inode_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_dentry_d_inode_offset(d_inode_offset));

    uint64_t inode_ptr = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(kpath.raw.dentry + d_inode_offset,&inode_ptr, sizeof(inode_ptr)));
    printf("inode_ptr: %lx\n", inode_ptr);

    uint32_t i_op_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_op_offset(i_op_offset));
    printf("i_op_offset: %u\n", i_op_offset);

    uint64_t i_op_ptr = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(inode_ptr + i_op_offset, &i_op_ptr, sizeof(i_op_ptr)));
    printf("i_op_ptr: %lx\n", i_op_ptr);

    uint32_t inode_operations_getattr_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_getattr_offset(inode_operations_getattr_offset));
    printf("inode_operations_getattr_offset: %u\n", inode_operations_getattr_offset);

    uint64_t i_op_getattr_ptr = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(i_op_ptr + inode_operations_getattr_offset, &i_op_getattr_ptr, sizeof(i_op_getattr_ptr)));
    printf("i_op_getattr_ptr: %lx\n", i_op_getattr_ptr);
    if (i_op_getattr_ptr < 0xFFFFFF0000000000) {
        printf("unknown i_op_getattr_ptr!\n");
        return KModErr::OK;
    }

    uint32_t kstat_ino_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_kstat_ino_offset(kstat_ino_offset));
    printf("kstat_ino_offset: %u\n", kstat_ino_offset);

    PatchBase patchBase;
    PatchInodeOperationsGetattr patchInodeOperationsGetattr(patchBase, i_op_getattr_ptr);
    KModErr err = patchInodeOperationsGetattr.patch_inode_operations_getattr(kstat_ino_offset, old_ino, new_ino);
    printf("patch inode_operations_getattr ret: %s\n", to_string(err).c_str());
    return KModErr::OK;
}

KModErr patch_kernel_handler(uint64_t old_ino, uint64_t new_ino) {
    KModErr err = patch_filldir64(old_ino, new_ino);
    RETURN_IF_ERROR(err);
    err = patch_compat_filldir(old_ino, new_ino);
    RETURN_IF_ERROR(err);
    err = patch_inode_op_getattr(old_ino, new_ino);
    RETURN_IF_ERROR(err);
    return KModErr::OK;
}

static bool get_dir_inode(const char* dir, uint64_t& inode) {
    if (dir == nullptr || dir[0] == '\0') return false;
    struct stat st {};
    if (::stat(dir, &st) != 0) {
        printf("stat failed: %s\n", dir);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        printf("not a directory: %s\n", dir);
        return false;
    }
    inode = static_cast<uint64_t>(st.st_ino);
    return true;
}

static uint64_t make_target_inode_value() {
    {
        uint64_t ino = 0;
        get_dir_inode(DATA_LOCAL_TRACES_DIR, ino);
        if(ino > 0 && ino < SAFE_INODE_RANGE) return ino - 1;
    }
    {
        uint64_t ino = 0;
        get_dir_inode(DATA_DATA_DIR, ino);
        if(ino > 0) return ino - 2;
    }
    return 0;
}

// 核心的检查与修复函数
static void check_and_fix_tmp_attrs(const char* dir) {
    struct stat st;
    if (::stat(dir, &st) == 0) {
        // 1. 检查并修复 UID 和 GID
        if (st.st_uid != TARGET_TMP_UID || st.st_gid != TARGET_TMP_GID) {
            printf("fixing UID/GID for %s (current: %d/%d, target: %d/%d)\n", dir, st.st_uid, st.st_gid, TARGET_TMP_UID, TARGET_TMP_GID);
            if (::chown(dir, TARGET_TMP_UID, TARGET_TMP_GID) != 0) {
                printf("[-] Failed to chown %s\n", dir);
            }
        }

        // 2. 检查并修复目录权限 (0771)
        // 使用 0777 掩码过滤掉 st_mode 中的文件类型标志，只保留权限位
        mode_t current_mode = st.st_mode & 0777;
        if (current_mode != TARGET_TMP_MODE) {
            printf("fixing permissions for %s (current: %04o, target: %04o)\n", dir, current_mode, TARGET_TMP_MODE);
            if (::chmod(dir, TARGET_TMP_MODE) != 0) {
                printf("failed to chmod %s\n", dir);
            }
        }
    } else {
        printf("[-] stat failed for %s, cannot check permissions/owners.\n", dir);
    }

    // 3. 检查并修复 SELinux Context
    std::string current_label;
    bool label_ok = file_utils::get_file_selinux_label(dir, current_label);
    if (!label_ok || current_label != TARGET_TMP_SELINUX_CTX) {
        printf("fixing selinux context for %s (current: %s, target: %s)\n", dir, current_label.empty() ? "NONE" : current_label.c_str(), TARGET_TMP_SELINUX_CTX);
        if (::setxattr(dir, XATTR_NAME_SELINUX, TARGET_TMP_SELINUX_CTX, strlen(TARGET_TMP_SELINUX_CTX) + 1, 0) != 0) {
            printf("[-] Failed to set SELinux context for %s\n", dir);
        }
    }
}
// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    if(!file_utils::is_dir(DATA_LOCAL_TMP_DIR)) {
        file_utils::delete_path(DATA_LOCAL_TMP_DIR);
        file_utils::create_directory_if_not_exists(DATA_LOCAL_TMP_DIR);
    }
    uint64_t ino_data_local_tmp = 0;
    get_dir_inode(DATA_LOCAL_TMP_DIR, ino_data_local_tmp);
    bool ino_safe = ino_data_local_tmp < SAFE_INODE_RANGE;
    printf("inode:%ld, safe:%d\n", ino_data_local_tmp, !!ino_safe);
    if(!ino_safe) {
        uint64_t new_ino = make_target_inode_value();
        printf("new inode:%ld\n", new_ino);
        KModErr err = patch_kernel_handler(ino_data_local_tmp, new_ino);
        printf("patch_kernel_handler ret:%s\n", to_string(err).c_str());
        if(is_failed(err)) return -1;
    }
    check_and_fix_tmp_attrs(DATA_LOCAL_TMP_DIR);
    return 0;
}

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("修复/data/local/tmp目录")
SKROOT_MODULE_VERSION("1.0.1")
SKROOT_MODULE_DESC("如果/data/local/tmp被删除过，可用本模块进行修复，本模块是内核级修复，稳定可靠。修复inode值、权限、selinux目录标签等。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("o9oOZyIQPHSKmlmmh4Gt9tNZ7KMNO0vo")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_repair_data_local_tmp/update.json")