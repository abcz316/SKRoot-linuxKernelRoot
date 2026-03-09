#pragma once
#include <stdio.h>
#include <iostream>
#include "kernel_module_kit_umbrella.h"

/***************************************************************************
 * Arm64ArgKind 参数类型枚举
 *   - XReg : 64 位通用寄存器（Xn）
 *   - WReg : 32 位通用寄存器（Wn）
 *   - Imm64: 64 位无符号立即数
 *   - Imm32: 32 位无符号立即数
 ***************************************************************************/
enum class Arm64ArgKind : uint8_t { XReg, WReg, Imm64, Imm32 };

/***************************************************************************
 * 统一参数载体
 ***************************************************************************/
struct Arm64Arg {
  using GpX = asmjit::a64::GpX;
  using GpW = asmjit::a64::GpW;
  Arm64ArgKind kind{};
  GpX x{};
  GpW w{};
  uint64_t imm64{};
  uint32_t imm32{};

  static Arm64Arg X(const GpX& r)    { Arm64Arg a; a.kind = Arm64ArgKind::XReg;  a.x = r; return a; }
  static Arm64Arg W(const GpW& r)    { Arm64Arg a; a.kind = Arm64ArgKind::WReg;  a.w = r; return a; }
  static Arm64Arg U64(uint64_t v)    { Arm64Arg a; a.kind = Arm64ArgKind::Imm64; a.imm64 = v; return a; }
  static Arm64Arg U32(uint32_t v)    { Arm64Arg a; a.kind = Arm64ArgKind::Imm32; a.imm32 = v; return a; }
  template<typename T>
  static Arm64Arg Ptr(T* p)          { return U64(reinterpret_cast<uint64_t>(p)); }

  void printf_msg() const {
    switch (kind) {
      case Arm64ArgKind::XReg:
        printf("XReg: %u\n", x.id());
        break;
      case Arm64ArgKind::WReg:
        printf("WReg: %u\n", w.id());
        break;
      case Arm64ArgKind::Imm64:
        printf("Imm64: %lu\n", imm64);
        break;
      case Arm64ArgKind::Imm32:
        printf("Imm32: %u\n", imm32);
        break;
    }
  }
};


inline Arm64Arg to_arg(const asmjit::a64::GpX& r){ return Arm64Arg::X(r); }
inline Arm64Arg to_arg(const asmjit::a64::GpW& r){ return Arm64Arg::W(r); }
inline Arm64Arg to_arg(uint64_t v)              { return Arm64Arg::U64(v); }
inline Arm64Arg to_arg(uint32_t v)              { return Arm64Arg::U32(v); }
inline Arm64Arg to_arg(const Arm64Arg& a)       { return a; }
template <class T>
inline std::enable_if_t<std::is_pointer_v<std::decay_t<T>>, Arm64Arg>
to_arg(T p) {
  return Arm64Arg::U64(reinterpret_cast<uint64_t>(p));
}

/***************************************************************************
 * 可变参收集器 mk_args(...)
 * 作用: 将任意数量、形态各异的参数（寄存器/立即数/指针/Arm64Arg）
 *       统一打包为 std::vector<Arm64Arg>
 ***************************************************************************/
template<class... Args>
static inline std::vector<Arm64Arg> mk_args(Args&&... args) {
    std::vector<Arm64Arg> v;
    v.reserve(sizeof...(Args));
    (v.emplace_back(to_arg(std::forward<Args>(args))), ...);
    return v;
}