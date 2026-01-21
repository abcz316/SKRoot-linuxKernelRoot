
#include "test_linux_kernel_api.h"
#include "test_linux_kernel_offset.h"
#include "test_string_ops.h"

KModErr Test_execute_kernel_asm_func() {
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	kernel_module::arm64_module_asm_func_start(a);
 	// nothing to do
	aarch64_asm_mov_x(a, x0, 0x12345);
	kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	uint64_t result = 0;
	RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
	printf("Shellcode output result: %s, value: %p\n", result == 0x12345 ? "ok" : "failed", (void*)result);
	return KModErr::OK;
}

KModErr Test_get_kernel_base_vaddr() {
	uint64_t kaddr = 0;
	RETURN_IF_ERROR(kernel_module::get_kernel_base_vaddr(kaddr));
	printf("Output addr: %p\n", (void*)kaddr);
	return KModErr::OK;
}

KModErr Test_alloc_kernel_mem() {
	uint64_t addr = 0;
	RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
	printf("Output addr: %p\n", (void*)addr);
	return KModErr::OK;
}

KModErr Test_free_kernel_mem() {
	uint64_t addr = 0;
	RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
	printf("Output addr: %p\n", (void*)addr);
	RETURN_IF_ERROR(kernel_module::free_kernel_mem(addr));
	return KModErr::OK;
}

KModErr Test_read_kernel_mem() {
	uint64_t addr = 0;
	RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(8, addr));
	printf("Output addr: %p\n", (void*)addr);

	std::vector<uint8_t> buf(8);
	RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
	printf("read_kernel_mem Buffer bytes:");
	for (size_t i = 0; i < buf.size(); ++i) {
		printf(" %02hhx", buf[i]);
	}
	printf("\n");
	return KModErr::OK;
}

KModErr Test_write_rw_kernel_mem() {
	uint32_t test_data[2] = {0xAABBCCDD, 0xEEFF1122};

	uint64_t addr = 0;
	RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(sizeof(test_data), addr));
	RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, &test_data, sizeof(test_data)));
	printf("Output addr: %p\n", (void*)addr);

	std::vector<uint8_t> buf(sizeof(test_data));
	RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
	printf("read_kernel_mem Buffer bytes:");
	for (size_t i = 0; i < buf.size(); ++i) {
		printf(" %02hhx", buf[i]);
	}
	printf("\n");
	return KModErr::OK;
}

KModErr Test_write_x_kernel_mem() {
	uint64_t kaddr = 0;
	RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("kernel_halt", kaddr));
	printf("Output addr: %p\n", (void*)kaddr);

 	// 读取原始内存内容
	uint8_t buf[16] = {0};
	RETURN_IF_ERROR(kernel_module::read_kernel_mem(kaddr, buf, sizeof(buf)));
	printf("read_kernel_mem (before) Buffer before:");
	for (size_t i = 0; i < sizeof(buf); ++i) {
		printf(" %02hhx", buf[i]);
	}
	printf("\n");

 	// 准备修改数据（8 字节）
	uint32_t ccmd[2] = { 0x11223344, 0x55667788 };
	RETURN_IF_ERROR(kernel_module::write_kernel_mem(kaddr, ccmd, sizeof(ccmd), kernel_module::KernMemProt::KMP_X));

 	// 再次读取内存以验证修改效果
	memset(buf, 0, sizeof(buf));
	RETURN_IF_ERROR(kernel_module::read_kernel_mem(kaddr, buf, sizeof(buf)));
	printf("read_kernel_mem (after) Buffer after:");
	for (size_t i = 0; i < sizeof(buf); ++i) {
		printf(" %02hhx", buf[i]);
	}
	printf("\n");
	return KModErr::OK;
}

KModErr Test_disk_storage() {
	if(getuid() != 0) {
		printf("[ERROR] Test this place, please run with ROOT permission.");
		return KModErr::ERR_MODULE_PARAM;
	}

	KModErr err = KModErr::ERR_MODULE_ASM;
	std::string str_value1;
	std::string str_value2;

 	// 读取已有值（如果不存在则忽略错误）
	err = kernel_module::read_string_disk_storage("testKey1", str_value1);
	if (is_failed(err) && err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) return err;

	err = kernel_module::read_string_disk_storage("testKey2", str_value2);
	if (is_failed(err) && err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) return err;

	printf("read_string_disk_storage Output string1: %s, string2: %s\n", str_value1.c_str(), str_value2.c_str());

 	// 写入新值
	std::string new_value1 = std::to_string(time(NULL));
	std::string new_value2 = new_value1;
	std::reverse(new_value2.begin(), new_value2.end());
	RETURN_IF_ERROR(kernel_module::write_string_disk_storage("testKey1", new_value1.c_str()));
	RETURN_IF_ERROR(kernel_module::write_string_disk_storage("testKey2", new_value2.c_str()));
	printf("write_string_disk_storage Write string1: %s, string2: %s\n", new_value1.c_str(), new_value2.c_str());
	return KModErr::OK;
}

std::vector<uint8_t> generate_filename_lookup_before_hook_bytes() {
	KModErr err = KModErr::OK;
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	kernel_module::arm64_before_hook_start(a);
	kernel_module::export_symbol::printk(a, err, "[!!!] test ok\n");
	kernel_module::arm64_before_hook_end(a, true);
	return aarch64_asm_to_bytes(a);
}

KModErr Test_install_kernel_function_before_hook() {
	using SymbolMatchMode = kernel_module::SymbolMatchMode;
	using SymbolHit = kernel_module::SymbolHit;

	SymbolHit hit;
	RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("filename_lookup", SymbolMatchMode::Prefix, hit));
	printf("%s, Output addr: %p\n", hit.name, (void*)hit.addr);

	std::vector<uint8_t> my_func_bytes = generate_filename_lookup_before_hook_bytes();
	KModErr err = kernel_module::install_kernel_function_before_hook(hit.addr, my_func_bytes);
	printf("install_kernel_function_before_hook return: %s\n", to_string(err).c_str());
	return err;
}

std::vector<uint8_t> generate_avc_denied_after_hook_bytes() {
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	kernel_module::arm64_after_hook_start(a);
	a->mov(x0, xzr);
	kernel_module::arm64_after_hook_end(a);
	return aarch64_asm_to_bytes(a);
}

KModErr Test_install_kernel_function_after_hook() {
	uint64_t avc_denied_addr = 0, ret_addr = 0;
	RETURN_IF_ERROR(kernel_module::get_avc_denied_kaddr(avc_denied_addr, ret_addr));
	printf("get_avc_denied_kaddr Output start addr: %p, ret addr: %p\n", (void*)avc_denied_addr, (void*)ret_addr);

	std::vector<uint8_t> my_func_bytes = generate_avc_denied_after_hook_bytes();
	KModErr err = kernel_module::install_kernel_function_after_hook(avc_denied_addr, my_func_bytes);
	printf("install_kernel_function_after_hook return: %s\n", to_string(err).c_str());
	return err;
}

int main(int argc, char *argv[]) {
 	//TODO: 在此修改你的Root key值。
	//fake_skroot_module_main("vzXtDKDAltAGxHtMGRZZfVouy90dgNqFsLM6UGeqb6OgH0VX");
	fake_skroot_module_main("GKAKERFc5as7v8IpNDtsx4vrdbWGuMqNjptIn9CwUikVA7yA");

 	// 单元测试：内核模块基础能力
	int idx = 1;
 	TEST(idx++, Test_execute_kernel_asm_func);				// 执行shellcode并获取返回值
 	TEST(idx++, Test_get_kernel_base_vaddr);				// 获取内核虚拟基址
 	TEST(idx++, Test_alloc_kernel_mem);						// 申请内核内存
 	TEST(idx++, Test_free_kernel_mem);						// 释放内核内存
 	TEST(idx++, Test_read_kernel_mem);						// 读取内核内存
 	TEST(idx++, Test_write_rw_kernel_mem);					// 写入内核内存(可读写区域)
 	TEST(idx++, Test_write_x_kernel_mem);					// 写入内核内存(仅执行区域)
 	TEST(idx++, Test_disk_storage);							// 读取、写入磁盘存储
 	TEST(idx++, Test_install_kernel_function_before_hook);	// 安装内核Hook（可在任意点位安装，执行前触发）
 	TEST(idx++, Test_install_kernel_function_after_hook);	// 安装内核Hook（在内核函数执行后触发）

 	// 单元测试: Linux内核API调用
 	TEST(idx++, Test_kallsyms_lookup_name1);				// 调用内核API：kallsyms_lookup_name
 	TEST(idx++, Test_kallsyms_lookup_name2);
 	TEST(idx++, Test_get_task_mm);							// 调用内核API：get_task_mm、mmput
 	TEST(idx++, Test_printk);								// 调用内核API：printf
 	TEST(idx++, Test_copy_from_user);						// 调用内核API：copy_from_user
 	TEST(idx++, Test_copy_to_user);							// 调用内核API：copy_to_user
 	TEST(idx++, Test_kmalloc1);								// 调用内核API：kmalloc
 	TEST(idx++, Test_kfree1);								// 调用内核API：kfree
 	TEST(idx++, Test_kmalloc2);
 	TEST(idx++, Test_kfree2);
 	TEST(idx++, Test_module_alloc1);						// 调用内核API：module_alloc
 	TEST(idx++, Test_module_memfree1);						// 调用内核API：module_memfree
 	TEST(idx++, Test_module_alloc2);
 	TEST(idx++, Test_module_memfree2);
 	TEST(idx++, Test_kallsyms_on_each_symbol1);				// 调用内核API：kallsyms_on_each_symbol
 	TEST(idx++, Test_kallsyms_on_each_symbol2);
 	TEST(idx++, Test_kern_path);							// 调用内核API：kern_path

 	// 单元测试：获取Linux内核结构体偏移量
 	TEST(idx++, Test_get_task_struct_pid_offset);			// 获取 task_struct 结构体中 pid 字段的偏移量
 	TEST(idx++, Test_get_task_struct_real_parent_offset);	// 获取 task_struct 结构体中 real_parent 字段的偏移量
 	TEST(idx++, Test_get_task_struct_comm_offset);			// 获取 task_struct 结构体中 comm 字段的偏移量
 	TEST(idx++, Test_get_task_struct_real_cred_offset);		// 获取 task_struct 结构体中 real_cred 字段的偏移量
 	TEST(idx++, Test_get_task_struct_mm_offset);			// 获取 task_struct 结构体中 mm 字段的偏移量
 	TEST(idx++, Test_get_task_struct_files_offset);			// 获取 task_struct 结构体中 files 字段的偏移量
 	TEST(idx++, Test_get_task_struct_tasks_offset);			// 获取 task_struct 结构体中 tasks 字段的偏移量
 	TEST(idx++, Test_get_cred_uid_offset);					// 获取 cred 结构体中 uid 字段的偏移量
 	TEST(idx++, Test_get_mm_struct_arg_offset);				// 获取 mm_struct 结构体中 arg_start\arg_end 字段的偏移量
 	TEST(idx++, Test_get_mm_struct_env_offset);				// 获取 mm_struct 结构体中 env_start\env_end 字段的偏移量
 	TEST(idx++, Test_get_mm_struct_pgd_offset);				// 获取 mm_struct 结构体中 pgd 字段的偏移量
 	TEST(idx++, Test_get_mm_struct_map_count_offset);		// 获取 mm_struct 结构体中 map_count 字段的偏移量
 	TEST(idx++, Test_get_mm_struct_rss_stat_offset);		// 获取 mm_struct 结构体中 map_count 字段的偏移量
 	TEST(idx++, Test_get_file_struct_fdtab_offset);			// 获取 file_struct 结构体中 fdtab 字段的偏移量
 	TEST(idx++, Test_get_fdtable_fd_offset);				// 获取 fdtable 结构体中 fd 字段的偏移量
 	TEST(idx++, Test_get_dentry_d_iname_offset);			// 获取 dentry 结构体中 d_iname 字段的偏移量
 	TEST(idx++, Test_get_file_f_path_offset);				// 获取 file 结构体中 f_path 字段的偏移量
 	TEST(idx++, Test_get_file_f_inode_offset);				// 获取 file 结构体中 f_inode 字段的偏移量
 	TEST(idx++, Test_get_vm_area_struct_vm_offset);			// 获取 vm_area_struct 结构体中 vm 字段的偏移量
 	TEST(idx++, Test_get_vm_area_struct_vm_file_offset);	// 获取 vm_area_struct 结构体中 vm_file 字段的偏移量
 	TEST(idx++, Test_get_inode_i_ino_offset);				// 获取 inode 结构体中 i_ino 字段的偏移量
 	TEST(idx++, Test_get_inode_i_size_offset);				// 获取 inode 结构体中 i_size 字段的偏移量
	TEST(idx++, Test_get_inode_time_offset);				// 获取 inode 结构体中 i_atime/i_mtime/i_ctime 字段的偏移量
 	TEST(idx++, Test_set_current_caps);						// 设置进程能力集
 	TEST(idx++, Test_set_current_process_name);				// 设置进程名

 	// 单元测试：内核字符串与内存操作
 	TEST(idx++, Test_kstrlen);
 	TEST(idx++, Test_kstrnlen1);
 	TEST(idx++, Test_kstrnlen2);
 	TEST(idx++, Test_kstrnlen3);
 	TEST(idx++, Test_kstrcmp1);
 	TEST(idx++, Test_kstrcmp2);
 	TEST(idx++, Test_kstrcmp3);
 	TEST(idx++, Test_kstrncmp1);
 	TEST(idx++, Test_kstrncmp2);
 	TEST(idx++, Test_kstrncmp3);
 	TEST(idx++, Test_kstrncmp4);
 	TEST(idx++, Test_kstrncmp5);
 	TEST(idx++, Test_kstrncmp6);
 	TEST(idx++, Test_kstrcpy);
 	TEST(idx++, Test_kstrncpy);
 	TEST(idx++, Test_kstrcat1);
 	TEST(idx++, Test_kstrcat2);
 	TEST(idx++, Test_kstrcat3);
 	TEST(idx++, Test_kstrcat4);
 	TEST(idx++, Test_kstrncat1);
 	TEST(idx++, Test_kstrncat2);
 	TEST(idx++, Test_kstrncat3);
 	TEST(idx++, Test_kstrncat4);
 	TEST(idx++, Test_kstrncat5);
 	TEST(idx++, Test_kstrstr1);
 	TEST(idx++, Test_kstrstr2);
 	TEST(idx++, Test_kstrstr3);
 	TEST(idx++, Test_kstrchr1);
 	TEST(idx++, Test_kstrchr2);
 	TEST(idx++, Test_kstrrchr1);
 	TEST(idx++, Test_kstrrchr2);
 	TEST(idx++, Test_kstrrchr3);
 	TEST(idx++, Test_kmemset1);
 	TEST(idx++, Test_kmemset2);
 	TEST(idx++, Test_kmemcmp1);
 	TEST(idx++, Test_kmemcmp2);
 	TEST(idx++, Test_kmemcmp3);
 	TEST(idx++, Test_kmemcpy);
 	TEST(idx++, Test_kmemmem1);
 	TEST(idx++, Test_kmemmem2);
 	TEST(idx++, Test_kmemmem3);
 	TEST(idx++, Test_kmemmem4);
 	TEST(idx++, Test_kmemmem5);
 	TEST(idx++, Test_kmemmem6);
 	TEST(idx++, Test_kmemmem7);
 	TEST(idx++, Test_kmemchr1);
 	TEST(idx++, Test_kmemchr2);
 	TEST(idx++, Test_kmemchr3);
 	TEST(idx++, Test_kmemrchr1);
 	TEST(idx++, Test_kmemrchr2);
 	TEST(idx++, Test_kmemrchr3);
 	TEST(idx++, Test_kstartswith1);
 	TEST(idx++, Test_kstartswith2);
 	TEST(idx++, Test_kendswith1);
 	TEST(idx++, Test_kendswith2);

	return 0;
}
