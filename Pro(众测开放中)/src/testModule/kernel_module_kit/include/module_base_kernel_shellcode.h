#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "kernel_module_kit_umbrella.h"

#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"
namespace kernel_module {
/***************************************************************************
 * 在内核态执行自定义 AArch64 汇编代码，不获取执行结果。
 *
 * 参数:
 *   emit_fn [输入] 汇编代码生成器，回调参数：
 *                  a：AArch64 汇编器，用于生成内核态执行的汇编代码。
 *                  返回 true 表示生成完成；返回 false 则中止执行，并返回 KModErr::ERR_MODULE_ASM。
 *
 * 寄存器说明：X0～X30 均可自由使用，无需手动保护。
 *
 * 返回: OK 表示成功；其它值为错误码。
 * 用法示例：
 *  return run_kernel_shellcode([](asmjit::a64::Assembler* a) -> bool {
 *      // TODO: 在此生成汇编函数体
 *      return true;
 *  });
 ***************************************************************************/
KModErr run_kernel_shellcode(std::function<bool(asmjit::a64::Assembler* a)> emit_fn);

/***************************************************************************
 * 在内核态执行自定义 AArch64 汇编代码，并返回指定寄存器的 64 位值。
 *
 * 参数:
 *   emit_fn [输入] 汇编代码生成器，回调参数：
 *                  a：AArch64 汇编器，用于生成内核态执行的汇编代码。
 *                  out_result_reg：指定需要读取的寄存器，默认为 X0，可修改为其它 GpX 寄存器。
 *                  返回 true 表示生成完成；返回 false 则中止执行，并返回 KModErr::ERR_MODULE_ASM。
 *
 *   out_result [输出] 接收汇编代码执行完毕后，指定寄存器中的 64 位值。
 *       仅当本函数返回 OK 时有效。
 *
 * 寄存器说明：X0～X30 均可自由使用，无需手动保护。
 *
 * 返回: OK 表示成功；其它值为错误码。
 *
 * 用法示例：
 *   // 示例1：不指定寄存器，默认读取 X0
 *   uint64_t result = 0;
 *   RETURN_IF_ERROR(run_kernel_shellcode_result_u64(
 *       [](Assembler* a, GpX&) -> bool {
 *           a->mov(x0, 123);
 *           return true;
 *       }, result));
 *   // result = 123
 *
 *   // 示例2：指定读取 X10 寄存器
 *   RETURN_IF_ERROR(run_kernel_shellcode_result_u64(
 *       [](Assembler* a, GpX& out_result_reg) -> bool {
 *           aarch64_asm_mov_x(a, x10, 0x1122334455667788ULL);
 *           out_result_reg = x10;
 *           return true;
 *       }, result));
 *   // result = 0x1122334455667788
 *
 *   // 示例3：将计算结果存入 X12，并读取其值
 *   RETURN_IF_ERROR(run_kernel_shellcode_result_u64(
 *       [](Assembler* a, GpX& out_result_reg) -> bool {
 *           a->mov(x8, 100);
 *           a->mov(x9, 23);
 *           a->add(x12, x8, x9);
 *           out_result_reg = x12;
 *           return true;
 *       }, result));
 *   // result = 123
 ***************************************************************************/
KModErr run_kernel_shellcode_result_u64(
   std::function<bool(asmjit::a64::Assembler* a, asmjit::a64::GpX& out_result_reg)> emit_fn,
   uint64_t& out_result);
}