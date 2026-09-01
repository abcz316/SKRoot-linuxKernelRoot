#include "patch_mtk_hbt_filldir64.h"
#include <vector>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchMtkHbtFilldir64::PatchMtkHbtFilldir64(const PatchBase& patch_base, uint64_t hbt_filldir64) : PatchBase(patch_base), m_hbt_filldir64(hbt_filldir64) {}

PatchMtkHbtFilldir64::~PatchMtkHbtFilldir64() {}

KModErr PatchMtkHbtFilldir64::generate_hook_fake_filldir64(const std::set<std::string>& names, const std::set<uint64_t>& ino_set, uint64_t & out_func_kaddr) {
	if(m_hbt_filldir64 == 0) return KModErr::ERR_MODULE_PARAM;

	GpX x1_name = x1;
	GpW w2_namelen = w2;
	GpX x4_ino = x4;

	std::vector<std::string> hide_names(names.begin(), names.end());
	std::vector<uint64_t> hide_inos(ino_set.begin(), ino_set.end());

	//生成Hook 裸函数汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_allow_visible = a->newLabel();
	
	aarch64_asm_bit_c(a);
	// 比较进程名，放行白名单进程名。
	emit_check_current_allow_visible_to_x10(a);
	a->cbnz(x10, L_allow_visible);

	// 按目录名称隐藏
	for (size_t i = 0; i < hide_names.size(); ++i) {
		Label L_next = a->newLabel();

		const auto& dir_name = hide_names[i];
		aarch64_asm_mov_w(a, w11, dir_name.length());
		a->cmp(w2_namelen, w11);
		a->b(CondCode::kNE, L_next); //下一个

		// memcmp key
		aarch64_asm_set_x_cstr_ptr(a, x12, dir_name);
		{
			RegProtectGuard g1(a, x0);
			kernel_module::string_ops::kmemcmp(a, x1_name, x12, x11);
			a->mov(x11, x0);
		}
		a->cbnz(x11, L_next); //不相等，下一个

		// 隐藏文件夹的返回
		if (kernel_module::is_kernel_version_less("6.1.0")) {
			a->mov(x0, xzr);
		} else {
			a->mov(x0, Imm(1));
		}
		a->ret(x30); // 因为这里是手写裸函数，所以直接返回
		a->bind(L_next);
	}
	
	// 按完整路径隐藏
	for (size_t i = 0; i < hide_inos.size(); ++i) {
		Label L_next = a->newLabel();
		aarch64_asm_mov_x(a, x11, hide_inos[i]);
		a->cmp(x4_ino, x11);
		a->b(CondCode::kNE, L_next); //下一个

		// 隐藏文件夹的返回
		if (kernel_module::is_kernel_version_less("6.1.0")) {
			a->mov(x0, xzr);
		} else {
			a->mov(x0, Imm(1));
		}
		a->ret(x30); // 因为这里是手写裸函数，所以直接返回
		a->bind(L_next);
	}
	
	a->bind(L_allow_visible);
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
