#include "patch_thermal_zone_get_temp.h"
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

在HOOK内核函数中：
1.必须要保存、恢复的寄存器：x0–x7、X19–X28、X29-X30
2.能自由修改、无需额外保存／恢复的寄存器是：x9–x15 或 x16–x17（IP0/IP1）
3.尽量避开使用的寄存器：x18

简而言之：X9到X15之间的寄存器可以随便用，其他寄存器需要先保存再用，用完需恢复。

ABI 规定哪些寄存器需要保存？
caller-saved（会被调用者破坏）：X0..X17、Q0..Q7
callee-saved（必须由被调函数保存）：X19..X29、Q8..Q15、SP、FP、LR
也就是说，像 get_task_mm 这种标准C函数，它自己保证不会破坏 callee-saved 寄存器。
*/

PatchThermalZoneGetTemp::PatchThermalZoneGetTemp(const PatchBase& patch_base, uint64_t thermal_zone_get_temp) : PatchBase(patch_base), m_thermal_zone_get_temp(thermal_zone_get_temp) {}

PatchThermalZoneGetTemp::~PatchThermalZoneGetTemp() {}

KModErr PatchThermalZoneGetTemp::patch_thermal_zone_get_temp() {
	KModErr err = KModErr::OK;
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label L_end = a->newLabel();
	kernel_module::arm64_before_hook_start(a);

	kernel_module::arm64hook_emit_load_original_func(a, x10);
	{
		RegProtectGuard g1(a, x1);
		a->blr(x10); // 手动调用一次内核原始获取温度函数。
	}
	a->cbnz(w0, L_end); // 返回值非0，代表不成功，则直接结束。

	a->ldr(w10, ptr(x1)); // 读取内核即将要输出的温度。
	
	aarch64_asm_mov_w(a, w11, 35000); // 低温区放行
	a->cmp(w10, w11);
	a->b(CondCode::kLE, L_end);

	aarch64_asm_mov_w(a, w11, 95000); // 熔断保护 (通用版底线 95度)
	a->cmp(w10, w11);
	a->b(CondCode::kGE, L_end);

	// 精细化系数 0.37 (37%)
    // 逻辑：(Real - 35) * 0.37 + 35
    // 效果：95度(真实) -> 59.1度(伪装)。
    // 这是一个巧妙的数值：平时奔放，极限时触发轻度温控保护主板。
    // int fake = 35000 + ((real - 35000) * 37 / 100);
	// kernel_module::export_symbol::printk(a, err, "[!!!] thermal_zone_get_temp real val: %d\n", w10);

	// (real - 35000)
	aarch64_asm_mov_w(a, w11, 35000);
	a->sub(w12, w10, w11);

	// (real - 35000) * 35
	aarch64_asm_mov_w(a, w11, 35);
	a->mul(w12, w12, w11);

	// (real - 35000) * 35 / 100
	aarch64_asm_mov_w(a, w11, 100);
	a->sdiv(w12, w12, w11);

	// 35000 + ((real - 35000) * 35 / 100)
	aarch64_asm_mov_w(a, w11, 35000);
	a->add(w12, w12, w11); 
	
	// kernel_module::export_symbol::printk(a, err, "[!!!] thermal_zone_get_temp fake val: %d\n", w12);

	a->str(w12, ptr(x1));

	a->bind(L_end);
	kernel_module::arm64_before_hook_end(a, false);
	return patch_kernel_before_hook(m_thermal_zone_get_temp, a);
}