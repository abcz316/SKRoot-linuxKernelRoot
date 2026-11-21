#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <functional>
#include <errno.h>
#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

namespace kernel_module {
typedef struct HookContext* HookHandle;

/***************************************************************************
 * Hook函数开始
 * 参数： a 		ASMJIT 汇编器上下文
 ***************************************************************************/
void arm64_before_hook_start(asmjit::a64::Assembler* a);

/***************************************************************************
 * Hook函数结束：可选择是否跳回原函数
 * 参数： a 					ASMJIT 汇编器上下文
 *  - continue_original = true  ：跳回原函数继续执行。
 *  - continue_original = false ：不跳回原函数，直接生成 RET 指令返回调用者。
 ***************************************************************************/
void arm64_before_hook_end(asmjit::a64::Assembler* a, bool continue_original);


/***************************************************************************
 * 安装内核Hook（可在任意点位安装，执行前触发）。
 *
 * 参数:
 *   kaddr [输入] 目标内核地址（指令地址/Hook 点位）。
 *
 *   handler_shellcode [输入] Hook 处理函数的机器码（shellcode）。
 *                             开头必须调用 arm64_before_hook_start，
 *                             结束时必须调用 arm64_before_hook_end。
 *
 *   out_hook_handle [输出] 成功时返回 Hook 句柄，用于后续卸载。如果传 nullptr 表示调用者不在乎卸载。
 *
 * 工作原理：将 kaddr 位置的1条指令（4字节）替换为1条 B 跳转指令，转入 Hook 处理代码。
 *
 * 返回: OK 表示安装成功；其它值为错误码。
 *
 * 用法示例：
 *   // 示例1：执行 Hook 代码后，跳回原函数继续执行
 *   arm64_before_hook_start(a);
 *   // TODO: 在此生成 Hook 汇编代码
 *   arm64_before_hook_end(a, true);
 *   RETURN_IF_ERROR(install_kernel_function_before_hook(kaddr, aarch64_asm_to_bytes(a)));
 *
 *   // 示例2：修改返回值，不跳回原函数
 *   arm64_before_hook_start(a);
 *   a->mov(x0, 0);
 *   arm64_before_hook_end(a, false);
 *   RETURN_IF_ERROR(install_kernel_function_before_hook(kaddr, aarch64_asm_to_bytes(a)));
 ***************************************************************************/
KModErr install_kernel_function_before_hook(uint64_t kaddr, const std::vector<uint8_t>& handler_shellcode, HookHandle* out_hook_handle = nullptr);


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
 * 安装内核Hook（在目标函数执行后触发）。
 *
 * 参数:
 *   target_func_kaddr [输入] 目标内核函数的起始地址（函数入口）。
 *
 *   handler_shellcode [输入] Hook 处理函数的机器码（shellcode）。
 *                             开头必须调用 arm64_after_hook_start，
 *                             结束时必须调用 arm64_after_hook_end。
 *
 *   out_hook_handle [输出] 成功时返回 Hook 句柄，用于后续卸载。如果传 nullptr 表示调用者不在乎卸载。
 *
 * 工作原理：将 target_func_kaddr 位置的1条指令（4字节）替换为1条 B 跳转指令，转入 Hook 处理代码。
 *
 * 返回: OK 表示安装成功；其它值为错误码。
 *
 * 用法示例：
 *   // 示例1：将原函数 X0 返回值修改为 123
 *   arm64_after_hook_start(a);
 *   a->mov(x0, 123);
 *   arm64_after_hook_end(a);
 *   RETURN_IF_ERROR(install_kernel_function_after_hook(target_func_kaddr, aarch64_asm_to_bytes(a)));
 *
 *   // 示例2：将原函数 X0 返回值加 1
 *   arm64_after_hook_start(a);
 *   a->add(x0, x0, 1);
 *   arm64_after_hook_end(a);
 *   RETURN_IF_ERROR(install_kernel_function_after_hook(target_func_kaddr, aarch64_asm_to_bytes(a)));
 ***************************************************************************/
KModErr install_kernel_function_after_hook(uint64_t target_func_kaddr, const std::vector<uint8_t>& handler_shellcode, HookHandle* out_hook_handle = nullptr);

/***************************************************************************
 * 卸载内核 Hook
 * 参数:
 *   handle     安装Hook时的句柄
 * 返回: OK 表示成功，其他值为错误码
 ***************************************************************************/
KModErr uninstall_kernel_hook(HookHandle handle);

/***************************************************************************
 * （可选）手动调用原函数。
 * 作用：在 Hook 处理代码中调用原函数（不会重复触发自身Hook）。
 *
 * 使用条件：
 *   - Hook 点位必须是目标函数的入口地址。
 *
 * 注意事项：
 *   - 本函数不会自动保护寄存器，需要保留的寄存器请自行保护。
 *   - Before Hook 中若已手动调用原函数，应使用 arm64_before_hook_end(a, false)，否则原函数会多执行一次，导致意外发生。
 *   - After Hook 中原函数已经执行完毕，再次调用会使原函数重复执行。
 *
 * 用法示例：
 *   // 示例1：手动调用原函数，并返回原函数结果
 *   arm64_before_hook_start(a);
 *   arm64_emit_call_original(a);
 *   arm64_before_hook_end(a, false);
 *   RETURN_IF_ERROR(install_kernel_function_before_hook(target_func_kaddr, aarch64_asm_to_bytes(a)));
 *
 *   // 示例2：手动调用原函数，并修改返回值
 *   arm64_before_hook_start(a);
 *   arm64_emit_call_original(a);
 *   a->mov(x0, 123);
 *   arm64_before_hook_end(a, false);
 *   RETURN_IF_ERROR(install_kernel_function_before_hook(target_func_kaddr, aarch64_asm_to_bytes(a)));
 *
 *   // 示例3：调用原函数时，保护需要保留的寄存器
 *   arm64_before_hook_start(a);
 *   {
 *       RegProtectGuard guard(a, x1, x2);
 *       arm64_emit_call_original(a);
 *   }
 *   arm64_before_hook_end(a, false);
 *   RETURN_IF_ERROR(install_kernel_function_before_hook(target_func_kaddr, aarch64_asm_to_bytes(a)));
 ***************************************************************************/
void arm64_emit_call_original(asmjit::a64::Assembler* a);

}
