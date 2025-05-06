#include "patch_kernel_root.h"
#include "analyze/base_func.h"
#include "analyze/analyze_kernel.h"
#include "analyze/ARM_asm.h"

#include "patch_do_execve.h"
#include "patch_avc_denied.h"

#include "3rdparty/find_mrs_register.h"
#pragma comment(lib, "3rdparty/capstone-4.0.2-win64/capstone.lib")


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

	std::cout << "本工具用于生成SKRoot ARM64 Linux内核ROOT提权代码 V4" << std::endl << std::endl;

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
	std::cout << "Parse cred offsert mode name: " << t_mode_name  << std::endl;

	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, t_mode_name, v_seccomp)) {
		std::cout << "Failed to parse seccomp offsert" << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "Parse seccomp offsert mode name: " << t_mode_name << std::endl;

	for (auto x = 0; x < v_cred.size(); x++) {
		std::cout << "cred_offset[" << x <<"]:" << v_cred[x] << std::endl;
	}
	
	for (auto x = 0; x < v_seccomp.size(); x++) {
		std::cout << "seccomp_offset[" << x <<"]:" << v_seccomp[x] << std::endl;
	}

	std::vector<patch_bytes_data> vec_patch_bytes_data;

	std::vector<size_t> v_hook_func_start_addr;
	if (analyze_kernel.is_kernel_version_less("5.5.0")) {
		v_hook_func_start_addr.push_back(0x300);
	}
	else if (analyze_kernel.is_kernel_version_less("6.0.0")) {
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

	//cfi bypass
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

	PatchDoExecve patchDoExecve(file_buf, sym, analyze_kernel);
	PatchAvcDenied patchAvcDenied(file_buf, sym, analyze_kernel);

	size_t first_hook_func_addr = v_hook_func_start_addr[0];
	size_t next_hook_func_addr = patchDoExecve.patch_do_execve(str_root_key, first_hook_func_addr, v_cred, v_seccomp, vec_patch_bytes_data);
	if (v_hook_func_start_addr.size() > 1) {
		next_hook_func_addr = v_hook_func_start_addr[1];
	}
	if (next_hook_func_addr) {
		next_hook_func_addr = patchAvcDenied.patch_avc_denied(next_hook_func_addr, v_cred, vec_patch_bytes_data);
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