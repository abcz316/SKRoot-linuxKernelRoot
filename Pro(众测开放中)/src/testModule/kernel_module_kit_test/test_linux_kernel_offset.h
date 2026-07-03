#include "kernel_module_kit_test.h"
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <inttypes.h>
#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

KModErr Test_get_task_struct_state_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_state_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_stack_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_stack_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_stack_size() {
    uint32_t size = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_stack_size(size));
    printf("Output size: 0x%x\n", size);
    return KModErr::OK;
}

KModErr Test_get_task_struct_ptrace_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_ptrace_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_pid_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_pid_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_real_parent_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_real_parent_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_comm_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_real_cred_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_real_cred_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_mm_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_mm_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_files_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_files_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_task_struct_tasks_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_tasks_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_cred_uid_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_cred_uid_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_cred_cap_inheritable_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_cred_cap_inheritable_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_mm_mt_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_mm_mt_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_mmap_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_mmap_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_pgd_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_pgd_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_map_count_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_map_count_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_total_vm_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_total_vm_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_rss_stat_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_rss_stat_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_arg_offset() {
    uint32_t arg_start_offset = 0, arg_end_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_arg_offset(arg_start_offset, arg_end_offset));
    printf("Output arg_start offset: 0x%x\n", arg_start_offset);
    printf("Output arg_end offset: 0x%x\n", arg_end_offset);
    return KModErr::OK;
}

KModErr Test_get_mm_struct_env_offset() {
    uint32_t env_start_offset = 0, env_end_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_mm_struct_env_offset(env_start_offset, env_end_offset));
    printf("Output env_start offset: 0x%x\n", env_start_offset);
    printf("Output env_end offset: 0x%x\n", env_end_offset);
    return KModErr::OK;
}

KModErr Test_get_file_struct_fdtab_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_struct_fdtab_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_fdtable_fd_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_fdtable_fd_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_dentry_d_iname_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_dentry_d_iname_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_path_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_path_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_inode_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_inode_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_op_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_op_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_flags_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_flags_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_mode_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_mode_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_pos_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_pos_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_cred_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_cred_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_private_data_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_private_data_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_file_f_mapping_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_f_mapping_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_vm_area_struct_vm_start_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t vm_start_offset = 0, vm_end_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_vm_area_struct_vm_start_offset(vm_start_offset, vm_end_offset));
    printf("Output vm_start_offset: 0x%x\n", vm_start_offset);
    printf("Output vm_end_offset: 0x%x\n", vm_end_offset);
    return KModErr::OK;
}

KModErr Test_get_vm_area_struct_vm_flags_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_vm_area_struct_vm_flags_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_vm_area_struct_vm_mm_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_vm_area_struct_vm_mm_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_vm_area_struct_vm_file_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_vm_area_struct_vm_file_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_mode_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_mode_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_opflags_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_opflags_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_op_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_op_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_sb_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_sb_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_mapping_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_mapping_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_ino_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_ino_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_rdev_offset() {
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_rdev_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_size_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_size_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_inode_time_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t i_atime_offset = 0, i_mtime_offset = 0, i_ctime_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_time_offset(i_atime_offset, i_mtime_offset, i_ctime_offset));
    printf("Output i_atime_offset: 0x%x\n", i_atime_offset);
    printf("Output i_mtime_offset: 0x%x\n", i_mtime_offset);
    printf("Output i_ctime_offset: 0x%x\n", i_ctime_offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_state_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t i_state_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_state_offset(i_state_offset));
    printf("Output i_state_offset: 0x%x\n", i_state_offset);
    return KModErr::OK;
}

KModErr Test_get_inode_i_bdev_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t i_bdev_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_i_bdev_offset(i_bdev_offset));
    printf("Output offset: 0x%x\n", i_bdev_offset);
    return KModErr::OK;
}

KModErr Test_get_inode_operations_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_lookup_offset(offset));
    printf("Output lookup offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_permission_offset(offset));
    printf("Output permission offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_getattr_offset(offset));
    printf("Output getattr offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_inode_operations_setattr_offset(offset));
    printf("Output setattr offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_super_block_s_uuid_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_super_block_s_uuid_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_super_block_s_dev_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_super_block_s_dev_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_proc_ops_offsets() {
    REQUIRE_ROOT_OR_RETURN();
    kernel_module::proc_ops_offsets offsets;
    RETURN_IF_ERROR(kernel_module::get_proc_ops_offsets(offsets));
    printf("Output proc_open_offset: 0x%x\n", offsets.proc_open_offset);
    printf("Output proc_read_offset: 0x%x\n", offsets.proc_read_offset);
    printf("Output proc_write_offset: 0x%x\n", offsets.proc_write_offset);
    printf("Output proc_lseek_offset: 0x%x\n", offsets.proc_lseek_offset);
    printf("Output proc_release_offset: 0x%x\n", offsets.proc_release_offset);
    printf("Output proc_poll_offset: 0x%x\n", offsets.proc_poll_offset);
    printf("Output proc_mmap_offset: 0x%x\n", offsets.proc_mmap_offset);
    return KModErr::OK;
}

KModErr Test_get_file_operations_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_llseek_offset(offset));
    printf("Output llseek offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_read_offset(offset));
    printf("Output read offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_write_offset(offset));
    printf("Output write offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_read_iter_offset(offset));
    printf("Output read_iter offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_write_iter_offset(offset));
    printf("Output write_iter offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_iterate_shared_offset(offset));
    printf("Output iterate_shared offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_unlocked_ioctl_offset(offset));
    printf("Output unlocked_ioctl offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_mmap_offset(offset));
    printf("Output mmap offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_poll_offset(offset));
    printf("Output poll offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_open_offset(offset));
    printf("Output open offset: 0x%x\n", offset);
    offset = 0;
    RETURN_IF_ERROR(kernel_module::get_file_operations_release_offset(offset));
    printf("Output release offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_miscdevice_offsets() {
    REQUIRE_ROOT_OR_RETURN();
    kernel_module::miscdevice_offsets offsets;
    RETURN_IF_ERROR(kernel_module::get_miscdevice_offsets(offsets));
    printf("Output minor_offset: 0x%x\n", offsets.minor_offset);
    printf("Output name_offset: 0x%x\n", offsets.name_offset);
    printf("Output fops_offset: 0x%x\n", offsets.fops_offset);
    printf("Output list_offset: 0x%x\n", offsets.list_offset);
    return KModErr::OK;
}

KModErr Test_get_seq_file_buf_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_seq_file_buf_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_seq_file_size_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_seq_file_size_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_seq_file_count_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_seq_file_count_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_renamedata_old_dir_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_renamedata_old_dir_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_address_space_host_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_address_space_host_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_address_space_i_mmap_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_address_space_i_mmap_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_block_device_bd_part_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_block_device_bd_part_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_block_device_bd_disk_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_block_device_bd_disk_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_gendisk_part0_offset1() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_gendisk_part0_ptr_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_gendisk_part0_offset2() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_gendisk_part0_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_seq_operations_show_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_seq_operations_show_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_get_kstat_ino_offset() {
    REQUIRE_ROOT_OR_RETURN();
    uint32_t offset = 0;
    RETURN_IF_ERROR(kernel_module::get_kstat_ino_offset(offset));
    printf("Output offset: 0x%x\n", offset);
    return KModErr::OK;
}

KModErr Test_set_current_caps() {
    kernel_module::caps_info caps;
    KModErr err = kernel_module::get_current_caps(caps);
    if(err == KModErr::OK) {
        printf("Inheritable: 0x%" PRIx64 "\n", caps.inheritable);
        printf("Permitted  : 0x%" PRIx64 "\n", caps.permitted);
        printf("Effective  : 0x%" PRIx64 "\n", caps.effective);
        printf("Bounding   : 0x%" PRIx64 "\n", caps.bounding);
        printf("Ambient    : 0x%" PRIx64 "\n", caps.ambient);
    }
    printf("get_current_caps return:%s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    caps.inheritable = 0x2FFFFFFFFF;
    caps.permitted = 0x2FFFFFFFFF;
    caps.effective = 0x2FFFFFFFFF;
    caps.bounding = 0x2FFFFFFFFF;
    caps.ambient = 0x2FFFFFFFFF;
    err = kernel_module::set_current_caps(caps);
    printf("set_current_caps return:%s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    err = kernel_module::get_current_caps(caps);
    if(err == KModErr::OK) {
        printf("Inheritable: 0x%" PRIx64 "\n", caps.inheritable);
        printf("Permitted  : 0x%" PRIx64 "\n", caps.permitted);
        printf("Effective  : 0x%" PRIx64 "\n", caps.effective);
        printf("Bounding   : 0x%" PRIx64 "\n", caps.bounding);
        printf("Ambient    : 0x%" PRIx64 "\n", caps.ambient);
    }
    return KModErr::OK;
}

KModErr Test_set_current_process_name() {
    RETURN_IF_ERROR(kernel_module::set_current_process_name("aaabbbddd"));
    std::string name = get_comm_prctl();
    bool ok = name == "aaabbbddd";
    printf("set_current_process_name result: %s, %s\n", name.c_str(), ok ? "ok" : "failed");
    return KModErr::OK;
}