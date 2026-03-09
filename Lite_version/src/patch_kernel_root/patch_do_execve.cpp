#pragma once
#include "patch_do_execve.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

#define MAX_ERRNO	4095
#define TIF_SECCOMP 11

PatchDoExecve::PatchDoExecve(const PatchBase& patch_base, const KernelSymbolOffset& sym) : PatchBase(patch_base) {
	init_do_execve_param(sym);
}
PatchDoExecve::~PatchDoExecve() {}

void PatchDoExecve::init_do_execve_param(const KernelSymbolOffset& sym) {
	if (m_kernel_ver_parser.is_kernel_version_less("3.14.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve_common;
		m_doexecve_reg_param.do_execve_filename_reg = 0;
		m_doexecve_reg_param.is_single_char_ptr = true;
	}
	if (m_kernel_ver_parser.is_kernel_version_less("3.19.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve_common;
		m_doexecve_reg_param.do_execve_filename_reg = 0;
	} else if (m_kernel_ver_parser.is_kernel_version_less("4.18.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat_common;
		m_doexecve_reg_param.do_execve_filename_reg = 1;
	} else if (m_kernel_ver_parser.is_kernel_version_less("5.9.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.__do_execve_file;
		m_doexecve_reg_param.do_execve_filename_reg = 1;
	} else {
		// default linux kernel useage
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat_common;
		m_doexecve_reg_param.do_execve_filename_reg = 1;
	}

	if (m_doexecve_reg_param.do_execve_addr == 0) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve;
		m_doexecve_reg_param.do_execve_filename_reg = 0;
	}
	if (m_doexecve_reg_param.do_execve_addr == 0) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat;
		m_doexecve_reg_param.do_execve_filename_reg = 1;
	}
	m_doexecve_reg_param.do_execve_addr = skip_pac_bti_at_func_start(m_doexecve_reg_param.do_execve_addr);
}

int PatchDoExecve::get_need_write_cap_cnt() {
	return get_cap_cnt();
}

size_t PatchDoExecve::patch_do_execve(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, size_t task_struct_seccomp_offset,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {

	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	int securebits_len = 4 + securebits_padding;
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_write_cap_cnt();

	size_t hook_jump_back_addr = m_doexecve_reg_param.do_execve_addr + 4;
	char empty_root_key_buf[ROOT_KEY_LEN] = { 0 };

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();
	int key_start = a->offset();
	a->embed((const uint8_t*)empty_root_key_buf, sizeof(empty_root_key_buf));
	a->mov(x0, x0);
	a->mov(x11, Imm(uint64_t(-MAX_ERRNO)));
	a->cmp(a64::x(m_doexecve_reg_param.do_execve_filename_reg), x11);
	a->b(CondCode::kCS, label_end);
	if (m_doexecve_reg_param.is_single_char_ptr) {
		a->mov(x11, a64::x(m_doexecve_reg_param.do_execve_filename_reg));
	} else {
		a->ldr(x11, ptr(a64::x(m_doexecve_reg_param.do_execve_filename_reg)));
	}
	int key_offset = key_start - a->offset();
	aarch64_asm_adr_x(a, x12, key_offset);
	a->bind(label_cycle_name);
	a->ldrb(w14, ptr(x11).post(1));
	a->ldrb(w15, ptr(x12).post(1));
	a->cmp(w14, w15);
	a->b(CondCode::kNE, label_end);
	a->cbnz(w15, label_cycle_name);
	emit_get_current(a, x12);
	a->ldr(x14, ptr(x12, task_struct_cred_offset));
	a->add(x14, x14, Imm(atomic_usage_len));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(wzr, ptr(x14).post(securebits_len));
	a->mov(x13, Imm(cap_ability_max));
	a->stp(x13, x13, ptr(x14).post(16));
	a->stp(x13, x13, ptr(x14).post(16));
	if (cap_cnt >= 5) {
		a->str(x13, ptr(x14).post(8));
	}
	if (!is_CONFIG_THREAD_INFO_IN_TASK()) {
		uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
		a->mrs(x13, sp_el0_id);
		a->and_(x13, x13, Imm((uint64_t)~(0x4000 - 1)));
		a->ldaxr(x14, ptr(x13));
		a->mov(x15, Imm((uint64_t)1ULL << TIF_SECCOMP));
		a->bic(x14, x14, x15);
		a->stlxr(x15, x14, ptr(x13));
	} else {
		a->ldaxr(x14, ptr(x12));
		a->mov(x15, Imm((uint64_t)1ULL << TIF_SECCOMP));
		a->bic(x14, x14, x15);
		a->stlxr(x15, x14, ptr(x12));
	}
	a->str(wzr, ptr(x12, task_struct_seccomp_offset));
	a->bind(label_end);
	aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(a) << std::endl;

	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_doexecve_reg_param.do_execve_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	str_bytes = str_bytes.substr(0, sizeof(empty_root_key_buf) * 2) + strHookOrigCmd + str_bytes.substr(sizeof(empty_root_key_buf) * 2 + 0x4 * 2);

	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_do_execve failed: not enough kernel space." << std::endl;
		return 0;
	}
	
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	patch_jump(m_doexecve_reg_param.do_execve_addr, hook_func_start_addr + sizeof(empty_root_key_buf), vec_out_patch_bytes_data);
	return shellcode_size;
}
