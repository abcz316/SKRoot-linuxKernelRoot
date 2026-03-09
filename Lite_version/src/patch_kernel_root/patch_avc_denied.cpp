#include "patch_avc_denied.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchAvcDenied::PatchAvcDenied(const PatchBase& patch_base, const SymbolRegion& avc_denied) : PatchBase(patch_base) {
	m_avc_denied = skip_pac_bti_at_func_start(avc_denied);
}

PatchAvcDenied::~PatchAvcDenied() {}

size_t PatchAvcDenied::patch_avc_denied(const SymbolRegion& hook_func_start_region, size_t current_avc_check_bl_func, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	std::vector<size_t> avc_denied_ret_addr = find_all_aarch64_ret_offsets(m_avc_denied.offset, m_avc_denied.size);
	if (avc_denied_ret_addr.empty()) {
		std::cout << "[发生错误] patch_avc_denied failed: RET instruction not found." << std::endl;
		return 0;
	}
	uint32_t ret_instr = *reinterpret_cast<const uint32_t*>(&m_file_buf[avc_denied_ret_addr[0]]);
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();

	Label label_end = a->newLabel();
	emit_safe_bl(a, hook_func_start_addr, current_avc_check_bl_func);
	a->cbz(x10, label_end);
	a->mov(w0, wzr);
	a->bind(label_end);
	if (aarch64_insn_is_ret(ret_instr)) a->ret(x30);
	else if (aarch64_insn_is_retaa(ret_instr)) aarch64_asm_retaa(a);
	else if (aarch64_insn_is_retab(ret_instr)) aarch64_asm_retab(a);
	std::cout << print_aarch64_asm(a) << std::endl;
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	for (size_t addr : avc_denied_ret_addr) {
		patch_jump(addr, hook_func_start_addr, vec_out_patch_bytes_data);
	}
	return shellcode_size;
}
