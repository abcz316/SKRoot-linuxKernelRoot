#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "kernel_module_kit_umbrella.h"

#include "____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"
namespace kernel_module {
// arm64模块汇编函数入口：保存调用函数上下文
void arm64_module_asm_func_start(asmjit::a64::Assembler* a);

// arm64模块函数结束：恢复调用函数上下文（可设置返回值）
void arm64_module_asm_func_end(asmjit::a64::Assembler* a);
void arm64_module_asm_func_end(asmjit::a64::Assembler* a, asmjit::a64::GpX return_x);

/***************************************************************************
 * 在内核态执行自定义 AArch64 汇编函数
 * 参数: func_bytes      待执行的内核函数机器码 (函数必须在开头调用 arm64_module_asm_func_start，结尾调用 arm64_module_asm_func_end，否则不合法)。
 *      output_result   [输出] 函数的 64 位返回值；仅当本函数返回 OK 时有效
 * 
 * 注意事项：
 *    本函数会自动保存/恢复 X0～X17、X29～X30。
 *    因此在汇编函数体内：X0～X17、X29～X30 可直接使用，无需额外保护。
 *    若需使用其它寄存器（例如 X18～X28），请自行保存/恢复（可使用 RegProtectGuard 等方式）。
 *
 * 返回: OK 表示成功；其它值为错误码
 * 
 * 用法示例：
 *  aarch64_asm_ctx asm_ctx = init_aarch64_asm();
 *  auto a = asm_ctx.assembler();
 *  arm64_module_asm_func_start(a);
 *  // TODO: 在此添加你的代码
 *  arm64_module_asm_func_end(a);
 *  uint64_t result = 0;
 *  execute_kernel_asm_func(aarch64_asm_to_bytes(a), result);
 ***************************************************************************/
KModErr execute_kernel_asm_func(const std::vector<uint8_t>& func_bytes, uint64_t & output_result);

}