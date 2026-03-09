#include <filesystem>
#include <vector>
#include <string>
#include <cstdio>

#include "kernel_struct_path_helper.h"
#include "fd_guard.h"

namespace fs = std::filesystem;

#define SK_DEBUG_MODE 
#ifdef SK_DEBUG_MODE
    #define LOG_DBG(fmt, ...) printf("      [Debug] " fmt, ##__VA_ARGS__)
#else
    #define LOG_DBG(fmt, ...) do {} while(0)
#endif

struct FakeFile {
    fs::path system_file_path;
    fs::path fake_file_path;
    FakeFile(fs::path target, fs::path source) 
        : system_file_path(std::move(target)), fake_file_path(std::move(source)) {}
};

KModErr kernel_hijack_file(const fs::path& system_file_path, const fs::path& fake_file_path) {
    std::error_code ec;
    if (!fs::exists(system_file_path, ec) || ec) return KModErr::ERR_MODULE_OPEN_FILE;
    if (!fs::exists(fake_file_path, ec) || ec) return KModErr::ERR_MODULE_OPEN_FILE;
    if (!fs::is_regular_file(system_file_path, ec) || ec) return KModErr::ERR_MODULE_OPEN_FILE;
    if (!fs::is_regular_file(fake_file_path, ec) || ec) return KModErr::ERR_MODULE_OPEN_FILE;
    
    uint32_t i_mapping_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_mapping_offset(i_mapping_offset));
    LOG_DBG("i_mapping_offset:%d\n", i_mapping_offset);

    uint32_t i_size_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_size_offset(i_size_offset));
    LOG_DBG("i_size_offset:%d\n", i_size_offset);

    int fd = open(system_file_path.c_str(), O_RDONLY);
    int fake_fd = open(fake_file_path.c_str(), O_RDONLY);

    fd_guard f(fd);
    fd_guard fake_f(fake_fd);

    scoped_kpath kpath;
    scoped_kpath fake_kpath;
    RETURN_IF_ERROR(acquire_kpath(system_file_path.c_str(), kpath));
    RETURN_IF_ERROR(acquire_kpath(fake_file_path.c_str(), fake_kpath));

    uint32_t d_inode_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_dentry_d_inode_offset(d_inode_offset));

    uint64_t inode_ptr = 0;
    uint64_t fake_inode_ptr = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(kpath.raw.dentry + d_inode_offset, &inode_ptr, sizeof(inode_ptr)));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(fake_kpath.raw.dentry + d_inode_offset, &fake_inode_ptr, sizeof(fake_inode_ptr)));
    LOG_DBG("inode:%lx\n", inode_ptr);
    LOG_DBG("fake_inode:%lx\n", fake_inode_ptr);

    uint64_t i_mapping_pptr = inode_ptr + i_mapping_offset;
    uint64_t i_mapping_ptr = 0;
    uint64_t fake_i_mapping_pptr = fake_inode_ptr + i_mapping_offset;
    uint64_t fake_i_mapping_ptr = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(i_mapping_pptr, &i_mapping_ptr, sizeof(i_mapping_ptr)));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(fake_i_mapping_pptr, &fake_i_mapping_ptr, sizeof(fake_i_mapping_ptr)));
    LOG_DBG("i_mapping_ptr:%lx\n", i_mapping_ptr);
    LOG_DBG("fake_i_mapping_ptr:%lx\n", fake_i_mapping_ptr);

    RETURN_IF_ERROR(kernel_module::write_kernel_rw_mem_atomic64(i_mapping_pptr, fake_i_mapping_ptr));
    
    uint64_t r = 0;
    RETURN_IF_ERROR(get_kernel_shellcode_u64_result([inode_ptr, i_mapping_pptr, i_mapping_ptr, fake_i_mapping_ptr](Assembler* a, GpX & x) -> KModErr {
        KModErr err = KModErr::ERR_MODULE_PARAM;
        aarch64_asm_mov_x(a, x10, i_mapping_ptr);
        kernel_module::export_symbol::invalidate_inode_pages2(a, err, x10);
        RETURN_IF_ERROR(err);
        return KModErr::OK;
    }, r));

    uint64_t i_size_pptr = inode_ptr + i_size_offset;
    uint64_t fake_i_size_pptr = fake_inode_ptr + i_size_offset;
    uint64_t fake_i_size = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(fake_i_size_pptr, &fake_i_size, sizeof(fake_i_size)));
    LOG_DBG("fake_i_size:%ld\n", fake_i_size);
    RETURN_IF_ERROR(kernel_module::write_kernel_rw_mem_atomic64(i_size_pptr, fake_i_size));
    
    kpath.release_kaddr();
    fake_kpath.release_kaddr();
    return KModErr::OK;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[SKRoot] Module Start: System File Fake Demo\n");
    
    fs::path base_dir = module_private_dir;

    // 演示替换 /system/etc/hosts，重启后 ping www.aaa316.com，显示 123.123.123.123 即成功伪造。
    std::vector<FakeFile> vec_fake_file = {
        // 格式: { 目标系统路径, 你的伪造文件路径 }
        { "/system/etc/hosts", base_dir / "hosts" },
        //{ "/system/framework/framework.jar", base_dir / "framework.jar" },
        //{ "/system/framework/services.jar", base_dir / "services.jar" },
        
        // 如果需要修改build.prop里的属性，则还需要同时使用resetprop进行修改，两个一起修改就可以做到无痕。
        // 这里伪造build.prop文件的目的是为了防止App利用漏洞提权到system权限，导致暴露身份; 
        //{ "/system/build.prop", base_dir / "build.prop" },
    };

    printf("[SKRoot] Loading file redirection rules...\n");
    for (const auto& item : vec_fake_file) {
        printf("  [+] Rule Added:\n");
        printf("      Target: %s\n", item.system_file_path.c_str());
        printf("      Source: %s\n", item.fake_file_path.c_str());
        KModErr err = kernel_hijack_file(item.system_file_path, item.fake_file_path);
        printf("      Result: [%s]\n", to_string(err).c_str());
    }
    printf("[SKRoot] All rules loaded.\n");
    return 0;
}

SKROOT_MODULE_NAME("系统文件伪造 Demo")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("内核级伪造 /system 只读文件，实现内容无痕篡改；无视任何文件校验，完美过所有侦测手段。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_UUID32("xhTxKsI5kHacgHJ04b5VhO4ffiOP4sdc")