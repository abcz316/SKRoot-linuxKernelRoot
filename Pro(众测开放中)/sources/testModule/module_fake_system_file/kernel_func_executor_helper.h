#pragma once
#include "kernel_module_kit_umbrella.h"

#include <functional>

static KModErr get_kernel_shellcode_u64_result(std::function<KModErr(asmjit::a64::Assembler* a, asmjit::a64::GpX & x)> fn, uint64_t & result) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    asmjit::a64::GpX x = asmjit::a64::x0;
    RETURN_IF_ERROR(fn(a, x));
    kernel_module::arm64_module_asm_func_end(a, x);
    return kernel_module::execute_kernel_asm_func(aarch64_asm_to_bytes(a), result);
}