#include "patch_kernel_root.h"
#include "analyze/base_func.h"
#include "analyze/symbol_analyze.h"
#include "patch_do_execve.h"
#include "patch_current_avc_check.h"
#include "patch_avc_denied.h"
#include "patch_audit_log_start.h"
#include "patch_filldir64.h"

#include "3rdparty/find_mrs_register.h"
#include "3rdparty/find_imm_register_offset.h"

struct PatchKernelResult {
	bool patched = false;
	size_t root_key_start = 0;
};

bool check_file_path(const char* file_path) {
	return std::filesystem::path(file_path).extension() != ".img";
}

bool parser_cred_offset(const std::vector<char>& file_buf, const SymbolRegion &symbol, std::string& mode_name, size_t& cred_offset) {
	using namespace a64_find_mrs_register;
	return find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, mode_name, cred_offset);
}

bool parse_cred_uid_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t cred_offset, size_t& cred_uid_offset) {
	using namespace a64_find_imm_register_offset;
	cred_uid_offset = 0;
	KernelVersionParser kernel_ver(file_buf);
	size_t min_off = 8;
	if (kernel_ver.is_kernel_version_less("6.6.8")) min_off = 4;

	std::vector<int64_t> candidate_offsets;
	if (!find_imm_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, candidate_offsets))
		return false;

	auto it = std::find(candidate_offsets.begin(), candidate_offsets.end(), cred_offset);
	if (it != candidate_offsets.end()) {
		for (++it; it != candidate_offsets.end(); ++it) {
			if (*it > 0x30 || *it < min_off) continue;
			cred_uid_offset = *it;
			break;
		}
	}
	return cred_uid_offset != 0;
}

bool parser_seccomp_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, std::string& mode_name, size_t& seccomp_offset) {
	using namespace a64_find_mrs_register;
	return find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, mode_name, seccomp_offset);
}

void cfi_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	if (sym.__cfi_check.offset) {
		PATCH_AND_CONSUME(sym.__cfi_check, patch_ret_cmd(file_buf, sym.__cfi_check.offset, vec_patch_bytes_data));
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
}

void huawei_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	if (sym.hkip_check_uid_root) {
		patch_ret_0_cmd(file_buf, sym.hkip_check_uid_root, vec_patch_bytes_data);
	}
	if (sym.hkip_check_gid_root) {
		patch_ret_0_cmd(file_buf, sym.hkip_check_gid_root, vec_patch_bytes_data);
	}
	if (sym.hkip_check_xid_root) {
		patch_ret_0_cmd(file_buf, sym.hkip_check_xid_root, vec_patch_bytes_data);
	}
}

PatchKernelResult patch_kernel_handler(const std::vector<char>& file_buf, size_t cred_offset, size_t cred_uid_offset, size_t seccomp_offset, KernelSymbolOffset& sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	KernelVersionParser kernel_ver(file_buf);
	PatchBase patchBase(file_buf, cred_uid_offset);
	PatchDoExecve patchDoExecve(patchBase, sym);
	PatchCurrentAvcCheck patchCurrentAvcCheck(patchBase);
	PatchAvcDenied patchAvcDenied(patchBase, sym.avc_denied);
	PatchAuditLogStart patchAuditLogStart(patchBase, sym.audit_log_start);
	PatchFilldir64 patchFilldir64(patchBase, sym.filldir64);

	bool patched = true;
	PatchKernelResult r;
	if (kernel_ver.is_kernel_version_less("6.1.0")) {
		SymbolRegion next_empty_region = { 0x200, 0x300 };
		if (sym.__cfi_check.offset) next_empty_region = sym.__cfi_check;
		auto start_b_location = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, 4);
		r.root_key_start = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchDoExecve.patch_do_execve(next_empty_region, cred_offset, seccomp_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, next_empty_region, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_core(next_empty_region, vec_patch_bytes_data));
		auto current_avc_check_bl_func = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchCurrentAvcCheck.patch_current_avc_check_bl_func(next_empty_region, cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAvcDenied.patch_avc_denied(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAuditLogStart.patch_audit_log_start(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		auto end_b_location = next_empty_region.offset;
		patchBase.patch_jump(start_b_location, end_b_location, vec_patch_bytes_data);
	} else if (sym.die.offset && sym.arm64_notify_die.offset && sym.__drm_printfn_coredump.offset) {
		r.root_key_start = sym.die.offset;
		PATCH_AND_CONSUME(sym.die, patchDoExecve.patch_do_execve(sym.die, cred_offset, seccomp_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, sym.die, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_jump(sym.die.offset, sym.arm64_notify_die.offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.arm64_notify_die, patchFilldir64.patch_filldir64_core(sym.arm64_notify_die, vec_patch_bytes_data));
		auto current_avc_check_bl_func = sym.__drm_printfn_coredump.offset;
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchCurrentAvcCheck.patch_current_avc_check_bl_func(sym.__drm_printfn_coredump, cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAvcDenied.patch_avc_denied(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAuditLogStart.patch_audit_log_start(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
	} else {
		patched = false;
	}
	r.patched = patched;
	return r;
}

void write_all_patch(const char* file_path, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	for (auto& item : vec_patch_bytes_data) {
		std::shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
		hex2bytes((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
		if (!write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2)) {
			std::cout << "写入文件发生错误" << std::endl;
		}
	}
	if (vec_patch_bytes_data.size()) {
		std::cout << "Done." << std::endl;
	}
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "本工具用于生成SKRoot(Lite) ARM64 Linux内核ROOT提权代码 V11" << std::endl << std::endl;

#ifdef _DEBUG
#else
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}
#endif

#ifdef _DEBUG
#else
	const char* file_path = argv[0];
#endif
	std::cout << file_path << std::endl << std::endl;
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

	SymbolAnalyze symbol_analyze(file_buf);
	if (!symbol_analyze.analyze_kernel_symbol()) {
		std::cout << "Failed to analyze kernel symbols" << std::endl;
		system("pause");
		return 0;
	}
	KernelSymbolOffset sym = symbol_analyze.get_symbol_offset();

	std::string t_mode_name;
	size_t cred_offset  = 0;
	size_t cred_uid_offset = 0;
	size_t seccomp_offset = 0;
	if (!parser_cred_offset(file_buf, sym.sys_getuid, t_mode_name, cred_offset)) {
		std::cout << "Failed to parse cred offsert" << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "parse cred offsert mode name: " << t_mode_name  << std::endl;

	if (!parse_cred_uid_offset(file_buf, sym.sys_getuid, cred_offset, cred_uid_offset)) {
		std::cout << "Failed to parse cred uid offsert" << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "cred uid offset:" << cred_uid_offset << std::endl;

	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, t_mode_name, seccomp_offset)) {
		std::cout << "Failed to parse seccomp offsert" << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "parse seccomp offsert mode name: " << t_mode_name << std::endl;
	std::cout << "cred offset:" << cred_offset << std::endl;
	std::cout << "seccomp offset:" << seccomp_offset << std::endl;

	std::vector<patch_bytes_data> vec_patch_bytes_data;
	cfi_bypass(file_buf, sym, vec_patch_bytes_data);
	huawei_bypass(file_buf, sym, vec_patch_bytes_data);

	size_t first_hook_start = 0;
	PatchKernelResult pr = patch_kernel_handler(file_buf, cred_offset, cred_uid_offset, seccomp_offset, sym, vec_patch_bytes_data);
	if (!pr.patched) {
		std::cout << "Failed to find hook start addr" << std::endl;
		system("pause");
		return 0;
	}

	std::string str_root_key;
	size_t is_need_create_root_key = 0;
	std::cout << std::endl << "请选择是否需要自动随机生成ROOT密匙（1需要；2不需要）：" << std::endl;
	std::cin >> std::dec >> is_need_create_root_key;
	if (is_need_create_root_key == 1) {
		str_root_key = generate_random_str(ROOT_KEY_LEN);
	} else {
		std::cout << "请输入ROOT密匙（48个字符的字符串，包含大小写和数字）：" << std::endl;
		std::cin >> str_root_key;
		std::cout << std::endl;
	}
	std::string write_key = str_root_key;
	write_key.erase(write_key.size() - 1);
	patch_data(file_buf, pr.root_key_start, (void*)write_key.c_str(), write_key.length() + 1, vec_patch_bytes_data);

	std::cout << "#获取ROOT权限的密匙(Key): " << str_root_key.c_str() << std::endl << std::endl;

	size_t need_write_modify_in_file = 0;
	std::cout << "#是否需要立即写入修改到文件？（1需要；2不需要）：" << std::endl;
	std::cin >> need_write_modify_in_file;
	if (need_write_modify_in_file == 1) {
		write_all_patch(file_path, vec_patch_bytes_data);
	}
	system("pause");
	return 0;
}