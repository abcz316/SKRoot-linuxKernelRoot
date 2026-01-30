#include "patch_base.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchBase::PatchBase() {}

PatchBase::PatchBase(const PatchBase& other) {}

PatchBase::~PatchBase() {}

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