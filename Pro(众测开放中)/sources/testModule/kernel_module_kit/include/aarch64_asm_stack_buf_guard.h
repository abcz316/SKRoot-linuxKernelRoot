#pragma once
#include <cstdint>
#include "kernel_module_kit_umbrella.h"

/***************************************************************************
 * AArch64 栈缓冲区守卫类
 * 作用：在 SP 栈上划出一段临时缓冲区；作用域结束自动释放并还原 SP。
 *
 * 注意事项: 仅生成 sp 的 sub/add 指令，不保存/恢复任何寄存器。
 * 
 * 用法示例：
 * {
 *   // Guard 作用域：此段内 buffer 有效；退出作用域自动回收栈空间，buffer 指针随即失效
 *   StackBufGuard s1(a, 8, x10);
 *   a->mov(x11, Imm(2));
 *   a->str(x11, ptr(x10));
 * }
 ***************************************************************************/
class StackBufGuard {
    using Asm = asmjit::a64::Assembler;
    using GpX = asmjit::a64::GpX;

public:
    /*************************************************************************
     * 构造函数
     * 参数: a        : asmjit::a64::Assembler 指针
     *       bytes    : 分配大小
     *       out_base : 输出寄存器，接收分配得到的 buffer 内存地址
     *************************************************************************/
    explicit StackBufGuard(Asm* a, uint32_t bytes, GpX out_base)
        : a_(a), bytes_(align16(bytes)) {

        if (!a_) return;

        if (bytes_ != 0) {
            emitSubSp(bytes_);
            active_ = true;
        }
        // 立刻把“分配后的 sp”写入 out_base（外部马上拿到 buffer 地址）
        a_->mov(out_base, asmjit::a64::sp);
    }

    // move-only
    StackBufGuard(const StackBufGuard&) = delete;
    StackBufGuard& operator=(const StackBufGuard&) = delete;

    StackBufGuard(StackBufGuard&& other) noexcept
        : a_(other.a_), bytes_(other.bytes_), active_(other.active_) {
        other.a_ = nullptr;
        other.bytes_ = 0;
        other.active_ = false;
    }

    StackBufGuard& operator=(StackBufGuard&& other) noexcept {
        if (this != &other) {
            cleanup();
            a_ = other.a_;
            bytes_ = other.bytes_;
            active_ = other.active_;
            other.a_ = nullptr;
            other.bytes_ = 0;
            other.active_ = false;
        }
        return *this;
    }

    ~StackBufGuard() { cleanup(); }

private:
    static uint32_t align16(uint32_t n) { return (n + 15u) & ~15u; }

    // AArch64 add/sub immediate 通常可编码 0..4095（12-bit），这里保守拆分，避免用临时寄存器
    void emitSubSp(uint32_t bytes) {
        uint32_t left = bytes;
        while (left) {
            uint32_t chunk = (left > 4095u) ? 4095u : left;
            a_->sub(asmjit::a64::sp, asmjit::a64::sp, chunk);
            left -= chunk;
        }
    }

    void emitAddSp(uint32_t bytes) {
        uint32_t left = bytes;
        while (left) {
            uint32_t chunk = (left > 4095u) ? 4095u : left;
            a_->add(asmjit::a64::sp, asmjit::a64::sp, chunk);
            left -= chunk;
        }
    }

    void cleanup() {
        if (!a_ || !active_) return;
        emitAddSp(bytes_);
        active_ = false;
        bytes_ = 0;
    }

private:
    Asm* a_ = nullptr;
    uint32_t bytes_ = 0;
    bool active_ = false;
};
