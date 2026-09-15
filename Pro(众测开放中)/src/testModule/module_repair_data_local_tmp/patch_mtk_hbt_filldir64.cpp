#include "patch_mtk_hbt_filldir64.h"
#include <vector>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchMtkHbtFilldir64::PatchMtkHbtFilldir64(const PatchBase& patch_base, uint64_t hbt_filldir64) : PatchBase(patch_base), m_hbt_filldir64(hbt_filldir64) {}

PatchMtkHbtFilldir64::~PatchMtkHbtFilldir64() {}

KModErr PatchMtkHbtFilldir64::generate_hook_fake_filldir64(uint64_t old_ino, uint64_t new_ino, uint64_t & out_func_kaddr) {
	if(m_hbt_filldir64 == 0) return KModErr::ERR_MODULE_PARAM;

	GpX x4_ino = x4;

	std::vector<std::string> hide_names(names.begin(), names.end());
	std::vector<uint64_t> hide_inos(ino_set.begin(), ino_set.end());

	//生成Hook 裸函数汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_allow_visible = a->newLabel();
	
	aarch64_asm_bit_c(a);

	aarch64_asm_mov_x(a, x10, old_ino);
	a->cmp(x4_ino, x10);
	a->b(CondCode::kNE, L_end);
	aarch64_asm_mov_x(a, x10, new_ino);
	a->mov(x4_ino, x10);
	
	aarch64_asm_mov_x(a, x10, m_hbt_filldir64);
	a->br(x10); //跳转到原始函数
	std::vector<uint8_t> shellcode = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(create_kcfi_kernel_function(m_hbt_filldir64, shellcode, out_func_kaddr));
	return KModErr::OK;
}

KModErr PatchMtkHbtFilldir64::create_kcfi_kernel_function(uint64_t reference_func, const std::vector<uint8_t>& shellcode, uint64_t& out_func_kaddr) {
    constexpr uint64_t KCFI_PREFIX_SIZE = sizeof(uint32_t);
	const uint64_t src_kcfi_addr = reference_func - KCFI_PREFIX_SIZE;
	const uint64_t generated_size = KCFI_PREFIX_SIZE + shellcode.size();

	uint64_t alloc_base = 0;
	RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(generated_size, alloc_base));

	const uint64_t generated_func = alloc_base + KCFI_PREFIX_SIZE;
	
	// Copy KCFI type-id from original function.
	uint32_t kcfi_type_id = 0;
	RETURN_IF_ERROR(kernel_module::read_kernel_mem(src_kcfi_addr, &kcfi_type_id, sizeof(kcfi_type_id)));
	RETURN_IF_ERROR(kernel_module::write_kernel_mem(alloc_base, &kcfi_type_id, sizeof(kcfi_type_id)));

	// Write generated function body.
	RETURN_IF_ERROR(kernel_module::write_kernel_mem(generated_func, shellcode.data(), shellcode.size()));
	RETURN_IF_ERROR(kernel_module::set_kernel_mem_protection(alloc_base, generated_size, kernel_module::KernMemProt::KMP_X));
	out_func_kaddr = generated_func;
	return KModErr::OK;
}
