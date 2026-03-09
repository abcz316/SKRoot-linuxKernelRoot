#include "patch_audit_log_start.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchAuditLogStart::PatchAuditLogStart(const PatchBase& patch_base, uint64_t audit_log_start) : PatchBase(patch_base) {
	m_audit_log_start_orig_entry_insn = *(uint32_t*)&m_file_buf[audit_log_start];
	m_audit_log_start = skip_pac_bti_at_func_start(audit_log_start);
}

PatchAuditLogStart::~PatchAuditLogStart() {}

size_t PatchAuditLogStart::patch_audit_log_start(const SymbolRegion& hook_func_start_region, size_t current_avc_check_bl_func, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	size_t hook_jump_back_addr = m_audit_log_start + 4;

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_end = a->newLabel();
	emit_safe_bl(a, hook_func_start_addr, current_avc_check_bl_func);
	a->cbz(x10, label_end);
	a->mov(w0, wzr);
	emit_ret_by_entry_insn(a, m_audit_log_start_orig_entry_insn);
	a->bind(label_end);
	a->mov(x0, x0);
	aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(a) << std::endl;
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_audit_log_start failed: not enough kernel space." << std::endl;
		return 0;
	}
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_audit_log_start), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	int end_order_len = a->offset() - 2 * 4;
	str_bytes = str_bytes.substr(0, (end_order_len) * 2) + strHookOrigCmd + str_bytes.substr((end_order_len + 4) * 2);
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_audit_log_start failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	patch_jump(m_audit_log_start, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}
