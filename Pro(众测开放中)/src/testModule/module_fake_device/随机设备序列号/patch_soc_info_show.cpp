#include "patch_soc_info_show.h"
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

PatchSocInfoShow::PatchSocInfoShow(const PatchBase& patch_base, uint64_t soc_info_show) : PatchBase(patch_base), m_soc_info_show(soc_info_show) {}

PatchSocInfoShow::~PatchSocInfoShow() {}

/*
static ssize_t soc_info_show(struct device *dev, struct device_attribute *attr, char *buf)

struct device_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct device *dev, struct device_attribute *attr,
			char *buf);
	ssize_t (*store)(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count);
};

struct attribute {
	const char		*name;
	umode_t			mode;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	bool			ignore_lockdep:1;
	struct lock_class_key	*key;
	struct lock_class_key	skey;
#endif
};

*/
KModErr PatchSocInfoShow::patch_soc_info_show(const std::string& fake_soc_sn) {
	GpX x1_attr = x1;
	GpX x2_buf = x2;

	// 生成Hook func汇编命令
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_end = a->newLabel();

	// 这里下面是内核态要运行的指令
	kernel_module::arm64_before_hook_start(a);

	aarch64_asm_mov_x(a, x10, 0xFFFF000000000000ULL);
	a->cmp(x1_attr, x10);
	a->b(CondCode::kLO, L_end);

	a->ldr(x11, ptr(x1_attr));
	a->cmp(x11, x10);
	a->b(CondCode::kLO, L_end);

	// key
	aarch64_asm_set_x_cstr_ptr(a, x12, "serial_number");
	{
		RegProtectGuard g1(a, x0);
		kernel_module::string_ops::kstrcmp(a, x11, x12);
		a->mov(x11, x0);
	}
	a->cbnz(x11, L_end); // 不是serial_number

	std::string fake_soc_sn_line = fake_soc_sn + "\n";
	aarch64_asm_set_x_cstr_ptr(a, x12, fake_soc_sn_line);
	{
		RegProtectGuard g1(a, x0);
		kernel_module::string_ops::kstrcpy(a, x2_buf, x12);
	}
	aarch64_asm_mov_x(a, x0, fake_soc_sn_line.length());
	kernel_module::arm64_before_hook_end(a, false); // 直接返回，不跳回原函数

	a->bind(L_end);
	kernel_module::arm64_before_hook_end(a, true); // 直接返回，跳回原函数
	return patch_kernel_before_hook(m_soc_info_show, a);
}