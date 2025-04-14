#include "base_func.h"
#include "analyze_kernel.h"

#include "ARM_asm.h"

#include "3rdparty/find_mrs_register.h"
#pragma comment(lib, "3rdparty/capstone-4.0.2-win64/capstone.lib")

struct patch_bytes_data {
	std::string str_bytes;
	size_t write_addr = 0;
};

size_t patch_do_execve(const std::vector<char>& file_buf, const std::string& str_root_key, size_t hook_func_start_addr,
	size_t do_execve_entry_addr,
	size_t do_execve_key_reg,
	std::string &t_mode_name,
	std::vector<size_t>& task_struct_offset_cred,
	std::vector<size_t> &task_struct_offset_seccomp,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t do_execve_entry_hook_jump_back_addr = do_execve_entry_addr + 4;

	std::string str_show_root_key_mem_byte = bytes_2_hex_str((const unsigned char*)str_root_key.c_str(), str_root_key.length());
	std::cout << "#生成的ROOT密匙字节集：" << str_show_root_key_mem_byte.c_str() << std::endl << std::endl;

	vec_out_patch_bytes_data.push_back({ str_show_root_key_mem_byte, hook_func_start_addr });

	size_t nHookFuncSize = str_root_key.length();
	hook_func_start_addr += nHookFuncSize;


	auto add_t_asm_offset = (task_struct_offset_cred.size() - 1) * 4;

	std::stringstream sstrAsm;

	sstrAsm
		<< "MOV X0, X0" << std::endl
		<< "STP X7, X8, [sp, #-16]!" << std::endl
		<< "STP X9, X10, [sp, #-16]!" << std::endl
		<< "STP X11, X12, [sp, #-16]!" << std::endl
		<< "MOV X7, 0xFFFFFFFFFFFFF001" << std::endl
		<< "CMP X"<< do_execve_key_reg <<", X7" << std::endl
		<< "BCS #" << 120 + add_t_asm_offset << std::endl
		<< "LDR X7, [X"<< do_execve_key_reg <<"]" << std::endl
		<< "CBZ X7, #" << 112 + add_t_asm_offset << std::endl
		<< "ADR X8, #-84" << std::endl
		<< "MOV X9, #0" << std::endl
		<< "LDRB W10, [X7, X9]" << std::endl
		<< "CBZ W10, #"<< 96 + add_t_asm_offset << std::endl
		<< "LDRB W11, [X8, X9]" << std::endl
		<< "CBZ W11, #"<< 88 + add_t_asm_offset << std::endl
		<< "CMP W10, W11" << std::endl
		<< "B.NE #"<< 80 + add_t_asm_offset << std::endl
		<< "ADD X9, X9, 1" << std::endl
		<< "CMP X9, #" << str_root_key.length() << std::endl
		<< "BLT #-32" << std::endl;
		sstrAsm << "MRS X8, SP_EL0" << std::endl;
		for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
			if (x != task_struct_offset_cred.size() - 1) {
				sstrAsm << "LDR X8, [X8, #" << task_struct_offset_cred[x] << "]" << std::endl;
			}
		}
		sstrAsm << "LDR X10, [X8, #" << task_struct_offset_cred[task_struct_offset_cred.size() -1] << "]" << std::endl
		<< "MOV X7, #4" << std::endl
		<< "MOV W9, WZR" << std::endl
		<< "STR W9, [X10, X7]" << std::endl
		<< "ADD X7, X7, 4" << std::endl
		<< "CMP X7, #40" << std::endl
		<< "BLT #-12" << std::endl
		<< "MOV W9, 0xFFFFFFFF" << std::endl
		<< "CMP X7, #80" << std::endl
		<< "BLT #-24" << std::endl
		<< "LDXR W10, [X8]" << std::endl
		<< "BIC W10, W10,#0xFFF" << std::endl
		<< "STXR W11, W10, [X8]" << std::endl
		<< "STR WZR, [X8, #" << task_struct_offset_seccomp[task_struct_offset_seccomp.size() - 1] << "]" << std::endl
		<< "STR XZR, [X8, #" << task_struct_offset_seccomp[task_struct_offset_seccomp.size() - 1] + 8 << "]" << std::endl
		<< "LDP X11, X12, [sp], #16" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "B #" << do_execve_entry_hook_jump_back_addr - (hook_func_start_addr + 0x9C + add_t_asm_offset) << std::endl;

	std::string strAsmCode = sstrAsm.str();
	std::cout << std::endl << strAsmCode << std::endl;

	std::string strBytes = AsmToBytes(strAsmCode);
	if(!strBytes.length()) {
		return 0;
	}
	
	nHookFuncSize = strBytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&file_buf[0] + do_execve_entry_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes_2_hex_str((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strHookOrigCmd + strBytes.substr(0x4 * 2);

	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });

	std::stringstream sstrAsm2;
	sstrAsm2
		<< "B #" << hook_func_start_addr - do_execve_entry_addr << std::endl;
	std::string strBytes2 = AsmToBytes(sstrAsm2.str());
	if(!strBytes2.length()) {
		return 0;
	}
	
	vec_out_patch_bytes_data.push_back({ strBytes2, do_execve_entry_addr });

	hook_func_start_addr += nHookFuncSize;
	return hook_func_start_addr;
}

size_t patch_avc_denied(const std::vector<char>& file_buf, size_t hook_func_start_addr, size_t avc_denied_entry_addr,
	std::string &t_mode_name,
	std::vector<size_t>& task_struct_offset_cred,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t avc_denied_entry_hook_jump_back_addr = avc_denied_entry_addr + 4;
	auto add_t_asm_offset = (task_struct_offset_cred.size() - 1) * 4;
	std::stringstream sstrAsm;
	sstrAsm
		<< "STP X7, X8, [sp, #-16]!" << std::endl
		<< "STP X9, X10, [sp, #-16]!" << std::endl;
		sstrAsm << "MRS X7, SP_EL0" << std::endl;
		for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
			if (x != task_struct_offset_cred.size() - 1) {
				sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[x] << "]" << std::endl;
			}
		}
		sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[task_struct_offset_cred.size() - 1] << "]" << std::endl
		<< "CBZ X7, #"<< 84 << std::endl
		<< "MOV X8, #4" << std::endl
		<< "MOV W9, WZR" << std::endl
		<< "LDR W10, [X7, X8]" << std::endl
		<< "CMP W10, W9" << std::endl
		<< "B.NE #" << 64 << std::endl
		<< "ADD X8, X8, 4" << std::endl
		<< "CMP X8, #36" << std::endl
		<< "BLT #-20" << std::endl
		<< "ADD X8, X8, 12" << std::endl
		<< "MOV X9, 0x3FFFFFFFFF" << std::endl
		<< "LDR X10, [X7, X8]" << std::endl
		<< "ADD X8, X8, 8" << std::endl
		<< "CMP X10, X9" << std::endl
		<< "B.CC #"<< 28 << std::endl
		<< "CMP X8, #72" << std::endl
		<< "BLT #-20" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV W0, WZR" << std::endl
		<< "RET" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV X0, X0" << std::endl
		<< "B #" << avc_denied_entry_hook_jump_back_addr - (hook_func_start_addr + 0x70 + add_t_asm_offset) << std::endl;
	std::string strAsmCode = sstrAsm.str();
	std::cout << std::endl << strAsmCode << std::endl;

	std::string strBytes = AsmToBytes(strAsmCode);
	if(!strBytes.length()) {
		return 0;
	}
	size_t nHookFuncSize = strBytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&file_buf[0] + avc_denied_entry_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes_2_hex_str((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strBytes.substr(0, (0x6C + add_t_asm_offset) * 2) + strHookOrigCmd + strBytes.substr((0x6C + add_t_asm_offset + 4) * 2);

	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });

	std::stringstream sstrAsm2;
	sstrAsm2
		<< "B #" << hook_func_start_addr - avc_denied_entry_addr << std::endl;
	std::string strBytes2 = AsmToBytes(sstrAsm2.str());
	if(!strBytes2.length()) {
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes2, avc_denied_entry_addr });
	hook_func_start_addr += nHookFuncSize;
	return hook_func_start_addr + nHookFuncSize;
}


size_t patch_ret_cmd(const std::vector<char> &file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	vec_out_patch_bytes_data.push_back({ "C0035FD6", start });
	size_t off = start + 4;
	return off;
}

size_t patch_ret_1_cmd(const std::vector<char> &file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	vec_out_patch_bytes_data.push_back({ "200080D2C0035FD6", start });
	size_t off = start + 4 * 2;
	return off;
}

bool parser_cred_offset(const std::vector<char> &file_buf, size_t start, std::string& mode_name, std::vector<size_t>& v_cred) {
	 return find_current_task_next_register_offset(file_buf, start, mode_name, v_cred);
}

bool parser_seccomp_offset(const std::vector<char> &file_buf, size_t start, std::string& mode_name, std::vector<size_t>& v_seccomp) {
	 return find_current_task_next_register_offset(file_buf, start, mode_name, v_seccomp);
}

bool check_file_path(const char* file_path) {
	size_t len = strlen(file_path);
	if (len > 4 && strcmp(file_path + len - 4, ".img") == 0) {
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "本工具用于生成SKRoot ARM64 Linux内核ROOT提权代码 V3" << std::endl << std::endl;

#ifdef _DEBUG
#else
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}
#endif

	const char* file_path = argv[0];
	if (!check_file_path(file_path)) {
		std::cout << "Please enter the correct Linux kernel binary file path. " << std::endl;
		std::cout << "For example, if it is boot.img, you need to first decompress boot.img and then extract the kernel file inside." << std::endl;
		system("pause");
		return 0;
	}

	std::vector<char> file_buf = read_file_buf(file_path);
	if (!file_buf.size()) {
		std::cout << "Fail to open file:" << file_path << std::endl;
		system("pause");
		return 0;
	}

	AnalyzeKernel analyze_kernel(file_buf);
	if (!analyze_kernel.analyze_kernel_symbol()) {
		std::cout << "Failed to analyze kernel symbols" << std::endl;
		system("pause");
		return 0;
	}
	KernelSymbolOffset sym = analyze_kernel.get_symbol_offset();

	std::cout << "_text:" << sym._text << std::endl;
	std::cout << "_stext:" << sym._stext << std::endl;
	std::cout << "die:" << sym.die << std::endl;

	std::cout << "__do_execve_file:" << sym.__do_execve_file << std::endl;
	std::cout << "do_execveat_common:" << sym.do_execveat_common << std::endl;
	std::cout << "do_execve_common:" << sym.do_execve_common << std::endl;
	std::cout << "do_execveat:" << sym.do_execveat << std::endl;
	std::cout << "do_execve:" << sym.do_execve << std::endl;

	std::cout << "avc_denied:" << sym.avc_denied << std::endl;
	std::cout << "revert_creds:" << sym.revert_creds << std::endl;
	std::cout << "prctl_get_seccomp:" << sym.prctl_get_seccomp << std::endl;
	std::cout << "__cfi_check:" << sym.__cfi_check << std::endl;
	std::cout << "__cfi_check_fail:" << sym.__cfi_check_fail << std::endl;
	std::cout << "__cfi_slowpath_diag:" << sym.__cfi_slowpath_diag << std::endl;
	std::cout << "__cfi_slowpath:" << sym.__cfi_slowpath << std::endl;
	std::cout << "__ubsan_handle_cfi_check_fail_abort:" << sym.__ubsan_handle_cfi_check_fail_abort << std::endl;
	std::cout << "__ubsan_handle_cfi_check_fail:" << sym.__ubsan_handle_cfi_check_fail << std::endl;
	std::cout << "report_cfi_failure:" << sym.report_cfi_failure << std::endl;

	std::string t_mode_name;
	std::vector<size_t> v_cred;
	std::vector<size_t> v_seccomp;
	if (!parser_cred_offset(file_buf, sym.revert_creds, t_mode_name, v_cred)) {
		std::cout << "Failed to parse cred offsert" << std::endl;
		system("pause");
		return 0;
	}
	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, t_mode_name, v_seccomp)) {
		std::cout << "Failed to parse seccomp offsert" << std::endl;
		system("pause");
		return 0;
	}

	for (auto x = 0; x < v_cred.size(); x++) {
		std::cout << "cred_offset[" << x <<"]:" << v_cred[x] << std::endl;
	}
	
	for (auto x = 0; x < v_seccomp.size(); x++) {
		std::cout << "seccomp_offset[" << x <<"]:" << v_seccomp[x] << std::endl;
	}

	std::vector<patch_bytes_data> vec_patch_bytes_data;

	//cfi bypass
	std::vector<size_t> v_hook_func_start_addr;

	if (analyze_kernel.is_kernel_version_less_equal("5.4.291")) {
		v_hook_func_start_addr.push_back(0x300);
	} else if (analyze_kernel.is_kernel_version_less_equal("5.19.17")) {
		if (sym.__cfi_check) {
			size_t hook_start = patch_ret_cmd(file_buf, sym.__cfi_check, vec_patch_bytes_data);
			v_hook_func_start_addr.push_back(hook_start);
		}
	}
	if (!v_hook_func_start_addr.size()) {
		if (sym.die) {
			v_hook_func_start_addr.push_back(sym.die);
		}
	}

	if (v_hook_func_start_addr.size() == 0) {
		std::cout << "Failed to find hook start addr" << std::endl;
		system("pause");
		return 0;
	}

	if (sym.__cfi_check_fail) {
		patch_ret_cmd(file_buf, sym.__cfi_check_fail, vec_patch_bytes_data);
	}
	if (sym.__cfi_slowpath_diag) {
		patch_ret_cmd(file_buf, sym.__cfi_slowpath_diag, vec_patch_bytes_data);
	}
	if (sym.__cfi_slowpath) {
		patch_ret_cmd(file_buf, sym.__cfi_slowpath, vec_patch_bytes_data);
	}
	if (sym.__ubsan_handle_cfi_check_fail_abort) {
		patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail_abort, vec_patch_bytes_data);
	}
	if (sym.__ubsan_handle_cfi_check_fail) {
		patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail, vec_patch_bytes_data);
	}
	if (sym.report_cfi_failure) {
		patch_ret_1_cmd(file_buf, sym.report_cfi_failure, vec_patch_bytes_data);
	}

	std::string str_root_key;
	size_t create_new_root_key = 0;
	std::cout << std::endl << "请选择是否需要自动随机生成ROOT密匙（1需要；2不需要）：" << std::endl;
	std::cin >> std::dec >> create_new_root_key;
	if (create_new_root_key == 1) {
		str_root_key = generate_random_root_key();
	} else {
		std::cout << "请输入ROOT密匙（48个字符的字符串，包含大小写和数字）：" << std::endl;
		std::cin >> str_root_key;
	}

	size_t do_execve_entry_addr;
	size_t do_execve_key_reg;

	if (analyze_kernel.is_kernel_version_less_equal("3.19.0")) {
		do_execve_entry_addr = sym.do_execve_common;
		do_execve_key_reg = 0;
	} else  if (analyze_kernel.is_kernel_version_less_equal("4.18.0")) {
		do_execve_entry_addr = sym.do_execveat_common;
		do_execve_key_reg = 1;
	} else if (analyze_kernel.is_kernel_version_less_equal("5.9.0")) {
		do_execve_entry_addr = sym.__do_execve_file;
		do_execve_key_reg = 1;
	} else {
		// default linux kernel useage
		do_execve_entry_addr = sym.do_execveat_common;
		do_execve_key_reg = 1;
	}
	
	if (do_execve_entry_addr == 0) {
		do_execve_entry_addr = sym.do_execve;
		do_execve_key_reg = 0;
	}
	if (do_execve_entry_addr == 0) {
		do_execve_entry_addr = sym.do_execveat;
		do_execve_key_reg = 1;
	}

	size_t first_hook_func_addr = v_hook_func_start_addr[0];
	size_t next_hook_func_addr = patch_do_execve(file_buf, str_root_key, first_hook_func_addr, do_execve_entry_addr, do_execve_key_reg, t_mode_name, v_cred, v_seccomp, vec_patch_bytes_data);
	if (v_hook_func_start_addr.size() > 1) {
		next_hook_func_addr = v_hook_func_start_addr[1];
	}
	if (next_hook_func_addr) {
		next_hook_func_addr = patch_avc_denied(file_buf, next_hook_func_addr, sym.avc_denied, t_mode_name, v_cred, vec_patch_bytes_data);
	}
	if (next_hook_func_addr == 0) {
		std::cout << "生成汇编代码失败！请检查输入的参数！" << std::endl;
		system("pause");
		return 0;
	}

	std::cout << "#获取ROOT权限的密匙：" << str_root_key.c_str() << std::endl << std::endl;

	size_t need_write_modify_in_file = 0;
	std::cout << "#是否需要立即写入修改到文件？（1需要；2不需要）：" << std::endl;
	std::cin >> need_write_modify_in_file;
	if (need_write_modify_in_file == 1) {
		for (auto& item : vec_patch_bytes_data) {
			std::shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
			hex2byte((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
			if (!write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2)) {
				std::cout << "写入文件发生错误" << std::endl;
			}
		}
	}
	if (vec_patch_bytes_data.size()) {
		std::cout << "Done." << std::endl;
	}
	system("pause");
	return 0;


}