#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <errno.h>
#include "____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

namespace kernel_module {
    
/***************************************************************************
 * Hook函数开始
 * 参数： a 		ASMJIT 汇编器上下文
 ***************************************************************************/
void arm64_before_hook_start(asmjit::a64::Assembler* a);

/***************************************************************************
 * Hook函数结束：可选择是否跳回原函数
 * 参数： a 					ASMJIT 汇编器上下文
 *  - continue_original = true  ：恢复现场并跳回原函数（从被覆盖指令后继续执行）
 *  - continue_original = false ：直接生成 RET，不再执行原函数，返回到调用者
 ***************************************************************************/
void arm64_before_hook_end(asmjit::a64::Assembler* a, bool continue_original);

/***************************************************************************
 * 安装内核Hook（可在任意点位安装，执行前触发）
 * 参数:
 *   kaddr				 目标内核地址（指令地址/Hook 点位）
 *   hook_handler_code	 Hook 处理函数的机器码（shellcode）。
 *                       （注意：Hook处理函数开头必须调用 arm64_before_hook_start，结尾必须调用 arm64_before_hook_end，否则不合法。）
 * 返回: OK 表示成功，其他值为错误码。
 * 
 * 工作原理：仅将 kaddr 位置的 1 条指令（4 字节）替换为单条 B 跳转指令，无任何性能损耗。
 * 
 * Hook处理函数示例：
 *   arm64_before_hook_start(a);
 *   // TODO: 在此开始编写代码
 *   arm64_before_hook_end(a, true);
 ***************************************************************************/
KModErr install_kernel_function_before_hook(uint64_t kaddr, const std::vector<uint8_t>& hook_handler_code);


/***************************************************************************
 * Hook函数开始
 * 参数： a 		ASMJIT 汇编器上下文
 ***************************************************************************/
void arm64_after_hook_start(asmjit::a64::Assembler* a);

/***************************************************************************
 * Hook函数结束
 * 参数： a			ASMJIT 汇编器上下文
 ***************************************************************************/
void arm64_after_hook_end(asmjit::a64::Assembler* a);

/***************************************************************************
 * 安装内核Hook（在内核函数执行后触发）
 * 参数:
 *   target_func_kaddr   目标内核函数的起始地址（函数入口）
 *   hook_handler_code   Hook 处理函数的机器码（shellcode）。
 *                       （注意：Hook处理函数开头必须调用 arm64_after_hook_start，结尾必须调用 arm64_after_hook_end，否则不合法。）
 * 返回: OK 表示成功，其他值为错误码
 * 
 * 工作原理：仅将 kaddr 位置的 1 条指令（4 字节）替换为单条 B 跳转指令，无任何性能损耗。
 *  
 * Hook处理函数示例：
 *   arm64_after_hook_start(a);
 *   // TODO: 在此开始编写代码
 *   arm64_after_hook_end(a);
 ***************************************************************************/
KModErr install_kernel_function_after_hook(uint64_t target_func_kaddr, const std::vector<uint8_t>& hook_handler_code);

/***************************************************************************
 * （可选）装载“原始函数入口地址”到寄存器 xReg
 * 作用：可在 Hook 处理函数内部，手动执行原始函数（不会再次命中本 Hook 导致死循环）
 *
 * 使用条件（重要）：
 *   - 仅适用于 Hook 点位为“目标函数入口地址”时使用。
 *   - 必须在 Hook 处理函数内部调用，如：arm64_before_hook_start() 与 arm64_before_hook_end() 之间、
 *      arm64_after_hook_start 与 arm64_after_hook_end之间调用。
 *
 * 注意事项：
 *   - 本函数只会覆盖 xReg，不会替你保存任何寄存器；需要保留的寄存器请在 blr 前自行保存。
 *   - 你需要显式写 a->blr(xReg) 才会真正执行原始函数一次。
 *   - 若你已手动 blr 执行过原始函数，则 arm64_before_hook_end 的 continue_original 参数需传 false，否则原始函数会再多执行一次，导致意外发生。
 *
 * 用法示例1：
 *   arm64_before_hook_start(a);
 *   arm64hook_emit_load_original_func(a, x16);
 *   a->blr(x16); // blr 会按 AAPCS64 调用约定破坏寄存器；如需保留寄存器，请在 blr 前保存寄存器（可使用 RegProtectGuard 等方式）。
 *   arm64_before_hook_end(a, false);
 *
 * 用法示例2：
 *   arm64_after_hook_start(a);
 *   arm64hook_emit_load_original_func(a, x16);
 *   a->blr(x16); // blr 会按 AAPCS64 调用约定破坏寄存器；如需保留寄存器，请在 blr 前保存寄存器（可使用 RegProtectGuard 等方式）。
 *   arm64_after_hook_end(a, false);
 ***************************************************************************/
void arm64hook_emit_load_original_func(asmjit::a64::Assembler* a, asmjit::a64::GpX xReg);

}
