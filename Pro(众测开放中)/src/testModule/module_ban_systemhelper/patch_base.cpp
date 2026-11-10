#include "patch_base.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchBase::PatchBase(uint32_t cred_offset, uint32_t euid_offset)
	: m_cred_offset(cred_offset), m_euid_offset(euid_offset) {}

PatchBase::PatchBase(const PatchBase& other)
	: m_cred_offset(other.m_cred_offset), m_euid_offset(other.m_euid_offset) {}

PatchBase::~PatchBase() {}

void PatchBase::emit_check_current_euid_to_x10(Assembler* a, uint32_t target_uid) {
	Label label_end = a->newLabel();

	a->mov(x10, Imm(0));
	kernel_module::export_symbol::get_current(a, x11);
	a->cbz(x11, label_end);

	// 取 current->cred 指针。
	a->ldr(x11, ptr(x11, m_cred_offset));
	a->cbz(x11, label_end);

	// 读 cred->euid 并与目标 uid 比较。
	a->ldr(w12, ptr(x11, m_euid_offset));
	aarch64_asm_mov_w(a, w13, target_uid);
	a->cmp(w12, w13);
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
