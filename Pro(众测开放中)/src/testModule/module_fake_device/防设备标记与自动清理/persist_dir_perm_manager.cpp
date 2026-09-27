#include "persist_dir_perm_manager.h"

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>

#include "patch_selinux_inode_permission.h"
#include "fd_guard.h"
#include "kernel_struct_path_helper.h"
#include "utils/process_utils.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;


#define	EACCES		13	/* Permission denied */

#define IOP_FASTPERM	0x0001
#define IOP_LOOKUP	0x0002
#define IOP_NOFOLLOW	0x0004
#define IOP_XATTR	0x0008
#define IOP_DEFAULT_READLINK	0x0010

#define KERNEL_MINORBITS 20
#define KERNEL_MINORMASK ((1u << KERNEL_MINORBITS) - 1)

namespace {
static uint32_t user_rdev_to_kernel_dev(dev_t rdev) {
    uint32_t maj = major(rdev);
    uint32_t min = minor(rdev);
    return ((maj << KERNEL_MINORBITS) | (min & KERNEL_MINORMASK));
}

} // namespace

KModErr PersistDirPermManager::patch_inode_permission_func(uint64_t control_kaddr, const std::string& test_comm) {
    uint64_t selinux_inode_permission = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("selinux_inode_permission", selinux_inode_permission));
    printf("selinux_inode_permission addr: %p\n", (void*)selinux_inode_permission);

    InodePatchOffsets off = {};
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(off.comm_offset));
    
    RETURN_IF_ERROR(kernel_module::get_inode_i_ino_offset(off.inode_i_ino));
    printf("i_ino offset: 0x%x\n", off.inode_i_ino);

    RETURN_IF_ERROR(kernel_module::get_inode_i_sb_offset(off.inode_i_sb));
    printf("i_sb offset: 0x%x\n", off.inode_i_sb);

    RETURN_IF_ERROR(kernel_module::get_super_block_s_dev_offset(off.super_block_s_dev));
    printf("s_dev offset: 0x%x\n", off.super_block_s_dev);

    const char* persist_dir = nullptr;
    struct stat st;
    for (const char* dir : kPersistDirs) {
        if (::stat(dir, &st) == 0) {
            persist_dir = dir;
            break;
        }
        printf("stat failed: %s\n", dir);
    }

    if (!persist_dir) {
        printf("stat all persist dirs failed\n");
        return KModErr::ERR_MODULE_OPEN_DIR;
    }
    
    printf("persist i_ino: %llu\n", (unsigned long long)st.st_ino);
    printf("persist s_dev: %llu\n", (unsigned long long)st.st_dev); 

    PatchBase patchBase;
    PatchSelinuxInodePermission p(patchBase, selinux_inode_permission);
    KModErr err = p.patch_selinux_inode_permission(st.st_ino, user_rdev_to_kernel_dev(st.st_dev), control_kaddr, test_comm, off);
    printf("patch selinux_inode_permission addr: %p ret: %s\n", (void*)selinux_inode_permission, to_string(err).c_str());
    RETURN_IF_ERROR(err);
    
    return KModErr::OK;
}

std::vector<uint8_t> PersistDirPermManager::generate_permission_fn_bytes(uint64_t control_kaddr, uint32_t permission_kcfi, uint32_t comm_offset, const std::string& test_comm) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    Label L_denied = a->newLabel();
	a->embed(reinterpret_cast<const uint8_t*>(&permission_kcfi), sizeof(permission_kcfi));
    aarch64_asm_bit_jc(a);

    aarch64_asm_mov_x(a, x10, control_kaddr);
    a->ldrb(w10, ptr(x10));
    a->cbnz(w10, L_denied);
    
    PatchBase::emit_check_current_comm_name_to_x10(a, comm_offset, test_comm);
	a->cbnz(x10, L_denied); // 测试程序，主动拦截。

    a->mov(x0, xzr);
    a->ret(x30);

    a->bind(L_denied);
    a->mov(x0, Imm(-EACCES));
    a->ret(x30);
    return aarch64_asm_to_bytes(a);
}

KModErr PersistDirPermManager::patch_inode_op_permission(uint64_t control_kaddr, const std::string& test_comm) {
    uint32_t comm_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(comm_offset));
    
    uint32_t permission_kcfi = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_permission_kcfi_hash(permission_kcfi));

    std::vector<uint8_t> permission_fn_bytes = generate_permission_fn_bytes(control_kaddr, permission_kcfi, comm_offset, test_comm);
    uint64_t permission_fn_head_kaddr = 0;
    uint64_t permission_fn_entry_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(permission_fn_bytes.size(), permission_fn_head_kaddr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(permission_fn_head_kaddr, permission_fn_bytes.data(), permission_fn_bytes.size()));
    RETURN_IF_ERROR(kernel_module::set_kernel_mem_protection(permission_fn_head_kaddr, permission_fn_bytes.size(), kernel_module::KernMemProt::KMP_X));
    permission_fn_entry_kaddr = permission_fn_head_kaddr + 4;

    const char* persist_dir = nullptr;
    int fd = -1;
    for (const char* dir : kPersistDirs) {
        fd = ::open(dir, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            persist_dir = dir;
            break;
        }
        printf("open failed: %s, errno=%d\n", dir, errno);
    }
    if (fd < 0 || !persist_dir) {
        printf("open all persist dirs failed\n");
        return KModErr::ERR_MODULE_OPEN_DIR;
    }
    fd_guard f(fd);
    scoped_kpath kpath;
    RETURN_IF_ERROR(acquire_kpath(persist_dir, kpath));

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

    uint32_t inode_operations_permission_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_permission_offset(inode_operations_permission_offset));
    printf("inode_operations_permission_offset: %u\n", inode_operations_permission_offset);

    uint64_t fake_i_op_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, fake_i_op_kaddr));
    RETURN_IF_ERROR(kernel_module::fill00_kernel_mem(fake_i_op_kaddr, 1024));

    std::vector<uint8_t> i_op_backup(512);
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(i_op_ptr, i_op_backup.data(), i_op_backup.size()));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(fake_i_op_kaddr, i_op_backup.data(), i_op_backup.size()));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(fake_i_op_kaddr + inode_operations_permission_offset, &permission_fn_entry_kaddr, sizeof(permission_fn_entry_kaddr)));
    printf("fake_i_op_kaddr: %lx\n", fake_i_op_kaddr);

    RETURN_IF_ERROR(kernel_module::write_kernel_rw_mem_atomic64(inode_ptr + i_op_offset, fake_i_op_kaddr));

    uint32_t i_opflags_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_opflags_offset(i_opflags_offset));
    printf("i_opflags_offset: %u\n", i_opflags_offset);

    uint16_t i_opflags = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(inode_ptr + i_opflags_offset, &i_opflags, sizeof(i_opflags)));
    printf("i_opflags before: 0x%x\n", i_opflags);

    i_opflags &= ~IOP_FASTPERM;
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(inode_ptr + i_opflags_offset, &i_opflags, sizeof(i_opflags)));
    printf("i_opflags after: 0x%x\n", i_opflags);

    return KModErr::OK;
}

KModErr PersistDirPermManager::patch_kernel_handler(uint64_t control_kaddr, const std::string& test_comm) {
    KModErr err = patch_inode_permission_func(control_kaddr, test_comm);
    printf("patch_inode_permission_func ret: %s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    err = patch_inode_op_permission(control_kaddr, test_comm);
    printf("patch_inode_op_permission ret: %s\n", to_string(err).c_str());
    // RETURN_IF_ERROR(err);
    return KModErr::OK;
}

uint64_t PersistDirPermManager::alloc_control_kaddr() {
    uint64_t control_kaddr = 0;
    if (is_ok(kernel_module::alloc_kernel_mem(1, control_kaddr))) {
        kernel_module::fill00_kernel_mem(control_kaddr, 1);
    }
    return control_kaddr;
}

bool PersistDirPermManager::init() {
    if (m_control_kaddr) {
        printf("PersistDirPermManager already initialized, control_kaddr=%lx\n", m_control_kaddr);
        return true;
    }
    uint64_t control_kaddr = alloc_control_kaddr();
    if (!control_kaddr) {
        printf("alloc control kaddr failed\n");
        return false;
    }
    std::string new_comm = process_utils::reset_random_process_name();
    if (is_failed(patch_kernel_handler(control_kaddr, new_comm))) {
        printf("patch_kernel_handler failed\n");
        // kernel_module::free_kernel_mem(m_control_kaddr);
        return false;
    }
    if (!verify_persist_not_open()) {
        printf("verify failed: persist dir still openable\n");
        return false;
    }
    printf("verify persist dir: success\n");
    m_control_kaddr = control_kaddr;
    return true;
}

bool PersistDirPermManager::lock() {
    return set_locked(true);
}

bool PersistDirPermManager::unlock() {
    return set_locked(false);
}

bool PersistDirPermManager::set_locked(bool locked) {
    if (!m_control_kaddr) {
        printf("PersistDirPermManager not initialized\n");
        return false;
    }
    char ch = locked ? '\x01' : '\x00';
    KModErr err = kernel_module::write_kernel_mem(m_control_kaddr, &ch, sizeof(ch));
    if (!is_ok(err)) {
        printf("write lock control failed: %s\n", to_string(err).c_str());
        return false;
    }
    printf("persist dir %s!\n", locked ? "lock" : "unlock");
    return true;
}

bool PersistDirPermManager::verify_persist_not_open() {
    const char* persist_dir = nullptr;
    struct stat st;
    for (const char* dir : kPersistDirs) {
        if (::stat(dir, &st) == 0) {
            persist_dir = dir;
            break;
        }
    }
    if (!persist_dir) {
        printf("persist dir is nullptr\n");
        return false;
    }

    errno = 0;
    int fd = open(persist_dir, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        printf("verify_protect: FAILED, open allowed, path=%s\n", persist_dir);
        close(fd);
        return false;
    }
    if (errno != EACCES) {
        printf("verify_protect: unexpected fail, path=%s errno=%d(%s)\n", persist_dir, errno, strerror(errno));
        return false;
    }
    return true;
}