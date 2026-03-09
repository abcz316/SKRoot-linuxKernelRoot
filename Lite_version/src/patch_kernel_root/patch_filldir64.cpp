#include "patch_filldir64.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchFilldir64::PatchFilldir64(const PatchBase& patch_base, size_t filldir64) : PatchBase(patch_base) {
	m_filldir64_orig_entry_insn = *(uint32_t*)&m_file_buf[filldir64];
	m_filldir64 = skip_pac_bti_at_func_start(filldir64);
}

PatchFilldir64::~PatchFilldir64() {}

size_t PatchFilldir64::patch_filldir64_root_key_guide(size_t root_key_mem_addr, const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	int root_key_adr_offset = root_key_mem_addr - (hook_func_start_addr + a->offset());
	aarch64_asm_adr_x(a, x11, root_key_adr_offset);
	std::cout << print_aarch64_asm(a) << std::endl;
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });

	patch_jump(m_filldir64, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}

size_t PatchFilldir64::patch_filldir64_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	size_t hook_jump_back_addr = m_filldir64 + 4;

	GpX x_name_arg = x1;
	GpW w_namelen_arg = w2;

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();

	a->cmp(w_namelen_arg, Imm(FOLDER_HEAD_ROOT_KEY_LEN));
	a->b(CondCode::kNE, label_end);
	a->mov(x12, Imm(0));
	a->bind(label_cycle_name);
	a->ldrb(w13, ptr(x_name_arg, x12));
	a->ldrb(w14, ptr(x11, x12));
	a->cmp(w13, w14);
	a->b(CondCode::kNE, label_end);
	a->add(x12, x12, Imm(1));
	a->cmp(x12, Imm(FOLDER_HEAD_ROOT_KEY_LEN));
	a->b(CondCode::kLT, label_cycle_name);
	if (m_kernel_ver_parser.is_kernel_version_less("6.1.0")) {
		a->mov(x0, xzr);
	} else {
		a->mov(x0, Imm(1));
	}
	emit_ret_by_entry_insn(a, m_filldir64_orig_entry_insn);
	a->bind(label_end);
	a->mov(x0, x0);
	aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(a) << std::endl;

	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_filldir64), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));

	int end_order_len = a->offset() - 2 * 4;
	str_bytes = str_bytes.substr(0, (end_order_len) * 2) + strHookOrigCmd + str_bytes.substr((end_order_len + 4) * 2);
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	return shellcode_size;
}