#include "patch_selinux_inode_permission.h"
#include <vector>
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

/*
在 AArch64（ARM64）架构中, 根据 AAPCS64 调用约定：
    X0–X7：传递参数和返回值
    X8：系统调用号或临时
    X9–X15：调用者易失（caller‑saved）临时寄存器
    X16–X17（IP0/IP1）：过程内调用临时寄存器，用于短期跳转代码
    X18：平台保留寄存器（platform register），arm64内核启用SCS时，会x18作为shadow call stack指针
    X19–X28：被调用者保存寄存器（callee‑saved）
    X29（FP）：帧指针
    X30（LR）：链接寄存器
    SP：栈指针

在Hook内核函数中：
1.必须要保存、恢复的寄存器：x0–x7、X19–X28、X29-X30
2.能自由修改、无需额外保存／恢复的寄存器是：x9–x17
3.尽量避开使用的寄存器：x18

简而言之：X9到X17之间的寄存器可以随便用，其他寄存器需要先保存再用，用完需恢复。

ABI 规定哪些寄存器需要保存？
caller-saved（会被调用者破坏）：X0..X17、Q0..Q7
callee-saved（必须由被调函数保存）：X19..X29、Q8..Q15、SP、FP、LR
也就是说，像 get_task_mm 这种标准C函数，它自己保证不会破坏 callee-saved 寄存器。


在线Linux内核源码预览，快速定位寻找查询Linux函数声明、实现的网址：
 https://elixir.bootlin.com/linux
android版本的差异内核源码浏览：
 https://android.googlesource.com/kernel/common/
*/

#define	EACCES		13	/* Permission denied */

PatchSelinuxInodePermission::PatchSelinuxInodePermission(const PatchBase& patch_base, uint64_t selinux_inode_permission) : PatchBase(patch_base), m_selinux_inode_permission(selinux_inode_permission) {}

PatchSelinuxInodePermission::~PatchSelinuxInodePermission() {}

KModErr PatchSelinuxInodePermission::patch_selinux_inode_permission(uint64_t target_i_ino, uint32_t target_s_dev, uint64_t control_kaddr, const std::string& test_comm, const InodePatchOffsets& off) {
	GpX x0_inode = x0;

	// 生成Hook func汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_force_check = a->newLabel();
	Label L_normal = a->newLabel();

	// 这里下面是内核态要运行的指令
	kernel_module::arm64_before_hook_start(a);
	
    PatchBase::emit_check_current_comm_name_to_x10(a, off.comm_offset, test_comm);
	a->cbnz(x10, L_force_check); // 测试程序，主动拦截。

	aarch64_asm_mov_x(a, x10, control_kaddr);
	a->ldrb(w10, ptr(x10));
	a->cbz(w10, L_normal);

	// check inode->i_ino
	a->bind(L_force_check);
	aarch64_asm_mov_x(a, x11, (uint64_t)off.inode_i_ino);
	a->add(x11, x0_inode, x11);
	a->ldr(x11, ptr(x11)); // ARM64 Linux内核里inode->i_ino是64位。

	aarch64_asm_mov_x(a, x12, target_i_ino);
	a->cmp(x11, x12);
	a->b(CondCode::kNE, L_normal);

	
	// check inode->i_sb->s_dev
	aarch64_asm_mov_x(a, x11, (uint64_t)off.inode_i_sb);
	aarch64_asm_mov_x(a, x12, (uint64_t)off.super_block_s_dev);
	a->add(x11, x0_inode, x11);
	a->ldr(x11, ptr(x11));
	a->add(x12, x11, x12);
	a->ldr(w12, ptr(x12));
	aarch64_asm_mov_w(a, w11, target_s_dev);
	a->cmp(w11, w12);
	a->b(CondCode::kNE, L_normal);
	
	a->mov(x0, Imm(-EACCES));
	kernel_module::arm64_before_hook_end(a, false); // 直接返回，不跳回原函数
	
	a->bind(L_normal);
	kernel_module::arm64_before_hook_end(a, true); // 正常返回
	return patch_kernel_before_hook(m_selinux_inode_permission, a);
}