#include "patch_compat_filldir.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchCompatFilldir::PatchCompatFilldir(const PatchBase& patch_base, const SymbolRegion& compat_filldir) : PatchBase(patch_base) {
	m_compat_filldir = compat_filldir;
	m_compat_filldir_epilogue = find_func_epilogue_offset(m_compat_filldir.offset, m_compat_filldir.size);
	m_compat_filldir = skip_pac_bti_at_func_start(m_compat_filldir);
}

PatchCompatFilldir::~PatchCompatFilldir() {}

size_t PatchCompatFilldir::patch_compat_filldir_root_key_guide(size_t root_key_mem_addr, const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) return 0;
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	std::vector<uint8_t> bytes = assemble_aarch64([=](asmjit::a64::Assembler* a) {
		int root_key_adr_offset = root_key_mem_addr - (hook_func_start_addr + a->offset());
		aarch64_asm_adr_x(a, x11, root_key_adr_offset);
		std::cout << print_aarch64_asm(a) << std::endl;
	});
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_compat_filldir failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });

	patch_jump(m_compat_filldir.offset, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}

size_t PatchCompatFilldir::patch_compat_filldir_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) return 0;
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	size_t hook_jump_back_addr = m_compat_filldir.offset + 4;

	GpX x_name_arg = x1;
	GpW w_namelen_arg = w2;

	size_t restore_insn_offset = 0;
	std::vector<uint8_t> bytes = assemble_aarch64([=, &restore_insn_offset](asmjit::a64::Assembler* a) {
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
		aarch64_asm_b(a, (int32_t)(m_compat_filldir_epilogue - (hook_func_start_addr + a->offset())));
		a->bind(label_end);
		restore_insn_offset = a->offset();
		a->mov(x0, x0);
		aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
		std::cout << print_aarch64_asm(a) << std::endl;
	});
	if (bytes.size() == 0) return 0;
	uint32_t orig_insn = 0;
	std::memcpy(&orig_insn, m_file_buf.data() + m_compat_filldir.offset, sizeof(orig_insn));

	std::memcpy(bytes.data() + restore_insn_offset, &orig_insn, sizeof(orig_insn));
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = bytes.size();
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_compat_filldir failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	return shellcode_size;
}