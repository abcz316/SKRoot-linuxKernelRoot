#include "patch_base.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchBase::PatchBase(uint32_t task_struct_offset_cred, uint32_t cred_euid_offset, uint32_t comm_offset, const std::string& whitelist_comm_name)
	: m_task_struct_offset_cred(task_struct_offset_cred),
	m_cred_euid_offset(cred_euid_offset),
	m_comm_offset(comm_offset),
	m_whitelist_comm_name(whitelist_comm_name) {}

PatchBase::PatchBase(const PatchBase& other)
	: m_task_struct_offset_cred(other.m_task_struct_offset_cred),
	m_cred_euid_offset(other.m_cred_euid_offset),
	m_comm_offset(other.m_comm_offset),
	m_whitelist_comm_name(other.m_whitelist_comm_name) {}

PatchBase::~PatchBase() {}

void PatchBase::emit_check_current_allow_visible_to_x10(Assembler* a) {
	uint64_t comm_name_arr[2] = {0};
	size_t copy_len = std::min(m_whitelist_comm_name.length(), (size_t)(MY_TASK_COMM_LEN - 1));
	memcpy(comm_name_arr, m_whitelist_comm_name.c_str(), copy_len);
	
	Label label_end = a->newLabel();

	a->mov(x10, Imm(0));
	kernel_module::export_symbol::get_current(a, x11, label_end);
	a->ldr(x12, ptr(x11, m_task_struct_offset_cred));
	a->ldr(w12, ptr(x12, m_cred_euid_offset)); // 读euid就够了
	a->cbnz(w12, label_end); // euid is not root

	// 比较下进程名，放行白名单进程名。
	aarch64_asm_mov_w(a, w12, m_comm_offset);
	a->add(x11, x11, x12); // 指针往后推
	a->ldr(x12, ptr(x11, 0));
	aarch64_asm_mov_x(a, x13, comm_name_arr[0]);
	a->cmp(x12, x13);
    a->b(CondCode::kNE, label_end);

	a->ldr(x12, ptr(x11, 8));
    aarch64_asm_mov_x(a, x13, comm_name_arr[1]);
    a->cmp(x12, x13);
    a->b(CondCode::kNE, label_end);
	a->mov(x10, Imm(1));
	a->bind(label_end);
}

KModErr PatchBase::patch_kernel_before_hook(uint64_t kaddr, const Assembler* a) {
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::install_kernel_function_before_hook(kaddr, bytes));
	return KModErr::OK;
}

KModErr PatchBase::patch_kernel_after_hook(uint64_t kaddr, const Assembler* a) {
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::install_kernel_function_after_hook(kaddr, bytes));
	return KModErr::OK;
}