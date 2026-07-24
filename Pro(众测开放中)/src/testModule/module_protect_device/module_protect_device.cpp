#include "patch_blkdev_open.h"
#include <unistd.h>
#include <cstdio>

#include "kernel_module_kit_umbrella.h"
#include "process_utils.h"
#include "block_device_manager.h"

#define MODULE_DEFAULT_DESC "内核级防黑砖保护，在内核层阻断恶意写入核心分区，防止设备变黑砖。开机1分钟后保护生效。双清后可恢复正常开机。保护后会影响系统升级、刷写。如非必要，建议不要长期安装本模块。"

#define MODULE_INITING_DESC "正在启动中，还需要%d秒"
#define MODULE_DELAY_START_SEC 60

// 开始修补内核
static KModErr patch_kernel_handler(const std::vector<block_device::DevNodeInfo>& dev_list,
                                    const std::string& test_comm,
                                    uint64_t control_kaddr) {
    uint64_t blkdev_open_sym = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("blkdev_open", blkdev_open_sym));
    printf("blkdev_open(sym) addr: %p\n", (void*)blkdev_open_sym);

    uint32_t comm_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(comm_offset));
    printf("comm offset: 0x%x\n", comm_offset);

    BlkdevOpenPatchOffsets off = {};
    RETURN_IF_ERROR(kernel_module::get_file_f_mode_offset(off.file_f_mode));
    printf("f_mode offset: 0x%x\n", off.file_f_mode);

    RETURN_IF_ERROR(kernel_module::get_inode_i_rdev_offset(off.inode_i_rdev));
    printf("i_rdev offset: 0x%x\n", off.inode_i_rdev);

    PatchBase patchBase(comm_offset);
    PatchBlkdevOpen patchBlkdevOpen(patchBase, blkdev_open_sym);
    KModErr err = patchBlkdevOpen.patch_blkdev_open(dev_list, test_comm, control_kaddr, off);
    printf("patch blkdev_open addr: %p ret: %s\n", (void*)blkdev_open_sym, to_string(err).c_str());
    RETURN_IF_ERROR(err);
    return KModErr::OK;
}

static uint64_t alloc_control_kaddr() {
    uint64_t control_kaddr = 0;
    if(is_ok(kernel_module::alloc_kernel_mem(1, control_kaddr))) {
        kernel_module::fill00_kernel_mem(control_kaddr, 1);
    }
    return control_kaddr;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
	kernel_module::set_current_module_description(MODULE_DEFAULT_DESC);
    std::string new_comm = process_utils::reset_random_process_name();
    if(new_comm.empty()) {
        printf("reset process name failed\n");
        return -1;
    }
    uint64_t control_kaddr = alloc_control_kaddr();
    if(!control_kaddr) {
        printf("alloc control kaddr failed\n");
        return -1;
    }

    block_device::BuildOptions build_options;
    build_options.mode = block_device::ProtectionMode::AntiBrick;
    build_options.protect_internal_disks = true;
    build_options.protect_internal_partitions = true;
    build_options.protect_mmc_boot_areas = true;
    build_options.protect_system_mappers = true;
    build_options.protect_unnamed_internal_partitions = true;

    block_device::DeviceProtectionManager device_manager(build_options);

    std::vector<block_device::DevNodeInfo> dev_list;
    if (!device_manager.build_protected_device_list(dev_list)) {
        printf("build_protected_device_list failed\n");
        return -1;
    }
    KModErr err = patch_kernel_handler(dev_list, new_comm, control_kaddr);
    printf("patch_kernel_handler ret: %s\n", to_string(err).c_str());
    if (!is_ok(err)) {
        printf("patch_kernel_handler failed\n");
        return -1;
    }

    if (!device_manager.verify_protected_devices_not_writable(dev_list)) {
        printf("patch blkdev_open verify failed: protected block device still writable-openable\n");
        return -1;
    }
    printf("verify protect: success\n");
	

    process_utils::fork_delayed_task(0, [control_kaddr] {
        int remain_sec = MODULE_DELAY_START_SEC;
        printf("[module_protect_device] enable after %d seconds\n", remain_sec);
        for (; remain_sec > 0; --remain_sec) {
            char initing_tips[128] = {};
            snprintf(initing_tips, sizeof(initing_tips), MODULE_INITING_DESC, remain_sec);
            kernel_module::set_current_module_description(initing_tips);
            sleep(1);
        }

        char ch = '\x01';
        KModErr err = kernel_module::write_kernel_mem(control_kaddr, &ch, 1);
        if (!is_ok(err)) {
            printf("[module_protect_device] enable switch failed: %s\n", to_string(err).c_str());
            return;
        }
        printf("[module_protect_device] enable switch\n");
        kernel_module::set_current_module_description(MODULE_DEFAULT_DESC);
    });
    return 0;
}

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("防格机 (防变黑砖)")
SKROOT_MODULE_VERSION("1.1.0")
SKROOT_MODULE_DESC(MODULE_DEFAULT_DESC)
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("BbA6MdJYoS2ggs58zU327m5ufBihCOrS")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_protect_device/update.json")