#include "patch_iterate_dir.h"
#include <vector>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;
namespace {
	struct dir_context {
		uint64_t actor;
		uint64_t pos;
	};
}


PatchIterateDir::PatchIterateDir(const PatchBase& patch_base, uint64_t iterate_dir) : PatchBase(patch_base), m_iterate_dir(iterate_dir) {}

PatchIterateDir::~PatchIterateDir() {}

KModErr PatchIterateDir::patch_iterate_dir(uint64_t original_filldir64, uint64_t target_filldir64) {
	GpX x1_ctx = x1;

	//生成Hook func汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_end = a->newLabel();
	kernel_module::arm64_before_hook_start(a);
	a->cbz(x1_ctx, L_end);

	a->ldr(x10, ptr(x1_ctx, offsetof(dir_context, actor)));
	aarch64_asm_mov_x(a, x11, original_filldir64);
	a->cmp(x10, x11);
	a->b(CondCode::kNE, L_end);

	aarch64_asm_mov_x(a, x11, target_filldir64);
	a->str(x11, ptr(x1_ctx, offsetof(dir_context, actor)));

	a->bind(L_end);
	kernel_module::arm64_before_hook_end(a, true);
	return patch_kernel_before_hook(m_iterate_dir, a);
}