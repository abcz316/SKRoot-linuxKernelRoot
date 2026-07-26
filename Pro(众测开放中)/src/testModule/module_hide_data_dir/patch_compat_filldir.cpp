#include "patch_compat_filldir.h"
#include <vector>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchCompatFilldir::PatchCompatFilldir(const PatchBase& patch_base, uint64_t compat_filldir) : PatchBase(patch_base), m_compat_filldir(compat_filldir) {}

PatchCompatFilldir::~PatchCompatFilldir() {}

KModErr PatchCompatFilldir::patch_compat_filldir(const std::set<std::string>& names, const std::set<uint64_t>& ino_set) {
	GpX x1_name = x1;
	GpW w2_namelen = w2;
	GpX x4_ino = x4;

	std::vector<std::string> hide_names(names.begin(), names.end());
	std::vector<uint64_t> hide_inos(ino_set.begin(), ino_set.end());

	// 生成Hook func汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_allow_visible = a->newLabel();

	// 这里下面是内核态要运行的指令
	kernel_module::arm64_before_hook_start(a);

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
		kernel_module::arm64_before_hook_end(a, false); // 直接返回，不跳回原函数

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
		kernel_module::arm64_before_hook_end(a, false); // 直接返回，不跳回原函数
		a->bind(L_next);
	}
	
	a->bind(L_allow_visible);
	kernel_module::arm64_before_hook_end(a, true); // 正常返回
	return patch_kernel_before_hook(m_compat_filldir, a);
}