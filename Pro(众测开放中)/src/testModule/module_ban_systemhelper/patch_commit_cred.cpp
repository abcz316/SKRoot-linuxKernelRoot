#include "patch_commit_cred.h"
#include <signal.h>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

/*
在 AArch64（ARM64）架构中, 根据 AAPCS64 调用约定：
    X0–X7：传递参数和返回值
    X8：系统调用号或临时
    X9–X15：调用者易失（caller‑saved）临时寄存器
    X16–X17（IP0/IP1）：过程内调用临时寄存器
    X18：平台保留寄存器（arm64 内核启用 SCS 时，x18 作为 shadow call stack 指针）
    X19–X28：被调用者保存寄存器（callee‑saved）
    X29（FP）：帧指针
    X30（LR）：链接寄存器

在 Hook 内核函数中：
    1. 必须要保存、恢复的寄存器：x0–x7、X19–X28、X29-X30
    2. 能自由修改、无需额外保存／恢复的寄存器是：x9–x17
    3. 尽量避开使用的寄存器：x18

简而言之：X9 到 X17 之间的寄存器可以随便用，其他寄存器需要先保存再用，用完需恢复。
*/

PatchCommitCred::PatchCommitCred(const PatchBase& patch_base, uint64_t commit_creds)
	: PatchBase(patch_base), m_commit_creds(commit_creds) {}

PatchCommitCred::~PatchCommitCred() {}

KModErr PatchCommitCred::patch_commit_cred(uint32_t target_uid) {
	KModErr err = KModErr::OK;
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_end = a->newLabel();

	kernel_module::arm64_after_hook_start(a);
	{
		RegProtectGuard g1(a, x0); // 保护 commit_creds 的返回值 X0。

		emit_check_current_euid_to_x10(a, target_uid);
		a->cbz(x10, L_end);

		// 命中目标 APP：强制发送 SIGKILL。
		if (kernel_module::is_kernel_version_less("5.3.0")) {
			// Linux < 5.3.0: void force_sig(int sig, struct task_struct *p)
			kernel_module::export_symbol::get_current(a, x11, L_end);
			kernel_module::export_symbol::linux_older::force_sig(a, err, static_cast<uint32_t>(SIGKILL), x11);
		} else {
			// Linux >= 5.3.0: void force_sig(int sig)
			kernel_module::export_symbol::linux_above_5_3_0::force_sig(a, err, static_cast<uint32_t>(SIGKILL));
		}
		RETURN_IF_ERROR(err);

		a->bind(L_end);
	}
	kernel_module::arm64_after_hook_end(a);
	return patch_kernel_after_hook(m_commit_creds, a);
}
