#include "patch_blkdev_open.h"
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
2.能自由修改、无需额外保存／恢复的寄存器是：x9–x15 或 x16–x17（IP0/IP1）
3.尽量避开使用的寄存器：x18

简而言之：X9到X15之间的寄存器可以随便用，其他寄存器需要先保存再用，用完需恢复。

ABI 规定哪些寄存器需要保存？
caller-saved（会被调用者破坏）：X0..X17、Q0..Q7
callee-saved（必须由被调函数保存）：X19..X29、Q8..Q15、SP、FP、LR
也就是说，像 get_task_mm 这种标准C函数，它自己保证不会破坏 callee-saved 寄存器。


在线Linux内核源码预览，快速定位寻找查询Linux函数声明、实现的网址：
 https://elixir.bootlin.com/linux
android版本的差异内核源码浏览：
 https://android.googlesource.com/kernel/common/
*/

#define FMODE_WRITE_BIT  1
#define FMODE_WRITE      (1u << FMODE_WRITE_BIT)
#define	EPERM		 1

PatchBlkdevOpen::PatchBlkdevOpen(const PatchBase& patch_base, uint64_t blkdev_open) : PatchBase(patch_base), m_blkdev_open(blkdev_open) {}

PatchBlkdevOpen::~PatchBlkdevOpen() {}

KModErr PatchBlkdevOpen::patch_blkdev_open(const std::vector<block_device::DevNodeInfo> & protect_dev, const std::string& test_comm, uint64_t control_kaddr, const BlkdevOpenPatchOffsets& off) {
	std::set<uint32_t> kernel_rdev_set;
    for (auto& dev : protect_dev) kernel_rdev_set.insert(dev.kernel_rdev);

	KModErr err = KModErr::ERR_MODULE_ASM;
	GpX x0_inode = x0;
	GpX x1_flip = x1;
	GpX x15_flag = x15;

	// std::vector<std::string> hide_dirs(hide_dir_list.begin(), hide_dir_list.end());

	// 生成Hook func汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_entry = a->newLabel();
	Label L_normal = a->newLabel();
	Label L_not_allow = a->newLabel();

	//这里下面是内核态要运行的指令
	kernel_module::arm64_before_hook_start(a);
	
	emit_check_current_comm_name_to_x10(a, test_comm);
	a->cbnz(x10, L_entry); // 测试程序，主动拦截。

	aarch64_asm_mov_x(a, x11, control_kaddr);
	a->ldrb(w11, ptr(x11));
	a->cbz(w11, L_normal);

	a->bind(L_entry);
	a->ldr(w11, ptr(x1_flip, off.file_f_mode));
	a->tbz(w11, FMODE_WRITE_BIT, L_normal); // no write

	// check inode->i_rdev
	aarch64_asm_mov_w(a, w11, off.inode_i_rdev);
	a->add(x12, x0_inode, x11);
	a->ldr(w11, ptr(x12)); // ARM64 Linux内核里inode->i_rdev是32位。

	for (auto& k_rdev: kernel_rdev_set) {
		aarch64_asm_mov_w(a, w12, k_rdev);
		a->cmp(w11, w12);
		a->b(CondCode::kEQ, L_not_allow);
	}
	a->b(L_normal);

	a->bind(L_not_allow);

	// DEBUG:
	// uint32_t pid_offset = 0;
	// uint32_t comm_offset = 0;
    // kernel_module::get_task_struct_pid_offset(pid_offset);
    // kernel_module::get_task_struct_comm_offset(comm_offset);
	// kernel_module::export_symbol::get_current(a, x10);
	// aarch64_asm_mov_x(a, x11, pid_offset);
	// a->add(x11, x10, x11);
	// a->ldr(w11, ptr(x11));
	// aarch64_asm_mov_x(a, x12, comm_offset);
	// a->add(x12, x10, x12);
	// aarch64_asm_mov_w(a, w13, off.inode_i_rdev);
	// a->add(x13, x0_inode, x13);
	// a->ldr(w13, ptr(x13));
	// 
	// kernel_module::export_symbol::printk(a, err, "[!!!] my blkdev_open stop pid:%d, comm:%s, i_rdev:%d\n", x11, x12, w13);
	// RETURN_IF_ERROR(err);
	
	a->mov(x0, Imm(-EPERM));
	kernel_module::arm64_before_hook_end(a, false);

	a->bind(L_normal);
	kernel_module::arm64_before_hook_end(a, true); // 正常返回
	return patch_kernel_before_hook(m_blkdev_open, a);
}