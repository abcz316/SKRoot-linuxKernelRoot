#pragma once
#include <cassert>
#include <set>
#include <type_traits>
#include <algorithm>
#include <cstdio>
#include "aarch64_asm_arg.h"
#include "kernel_module_kit_umbrella.h"

/***************************************************************************
 * AArch64 空闲通用寄存器池
 * 作用: 管理一组“可临时占用”的 AArch64 通用寄存器 (Xn / Wn)，用于 JIT 生成。
 *    支持从显式寄存器集合或从调用参数向量 (std::vector<Arm64Arg>) 初始化，
 *    自动标记已被使用的寄存器，避免冲突。
 ***************************************************************************/
class IdleRegPool {
	using GpX = asmjit::a64::GpX;
	using GpW = asmjit::a64::GpW;
public:

  /***************************************************************************
   * 根据传入的 GpX / GpW 寄存器构造 IdleRegPool
   *
   * 原理: 先对池进行默认初始化（可用寄存器集合 = {x0..x28 except x18}）；
   *    然后将传入的寄存器标记为“已使用”，从可用集合中移除；
   *    返回一个按当前使用情况初始化好的寄存器池。
   *
   * 要求：Regs... 中每个参数的类型必须是 GpX 或 GpW（decay 之后判断）。
   ***************************************************************************/
  template <typename... Regs,
      typename = std::enable_if_t<(std::conjunction_v<
      std::bool_constant<std::is_same_v<std::decay_t<Regs>, GpX> || std::is_same_v<std::decay_t<Regs>, GpW>>...
      >)>>
  static IdleRegPool make(Regs... regs) {
    IdleRegPool p;
    p.init();
    (p.useOne(regs), ...);
    return p;
  }
  
  /***************************************************************************
   * 根据 Arm64Arg 参数推导出“已占用寄存器”，并构造 IdleRegPool
   *
   * 说明：对于 kind 为 XReg / WReg 的参数，从池中移除对应编号；
   *    其它 kind（Imm32 / Imm64）不影响寄存器占用状态；
   * 返回值：基于当前参数使用情况初始化好的寄存器池。
   ***************************************************************************/
  static IdleRegPool makeFromVec(const std::vector<Arm64Arg>& vec) {
    IdleRegPool p;
    p.init();
    for (auto& a : vec) {
      if (a.kind == Arm64ArgKind::XReg) p.useOne(a.x);
      else if (a.kind == Arm64ArgKind::WReg) p.useOne(a.w);
    }
    return p;
  }

  /*************************************************************************
   * 申请一个空闲 X 寄存器，并标记为已使用，返回对应的 GpX。
   *************************************************************************/
  GpX acquireX() {
    auto it = nextFree();
    if (it == free_.end()) printf("IdleRegPoo pool is empty!\n");
    uint32_t idx = *it;
    free_.erase(idx);
    used_.insert(idx);
    return asmjit::a64::x(idx);
  }

  /*************************************************************************
   * 申请一个空闲 W 寄存器，并标记为已使用，返回对应的 GpW。
   *************************************************************************/
  GpW acquireW() {
    auto it = nextFree();
    if (it == free_.end()) printf("IdleRegPool pool is empty!\n");
    uint32_t idx = *it;
    free_.erase(idx);
    used_.insert(idx);
    return asmjit::a64::w(idx);
  }

  /*************************************************************************
   * 归还一个 X 寄存器，并标记为“空闲”。
   *************************************************************************/
  void release(GpX x) {
    free_.insert(x.id());
    used_.erase(x.id());
  }

  /*************************************************************************
   * 归还一个 W 寄存器，并标记为“空闲”。
   *************************************************************************/
  void release(GpW w) {
    free_.insert(w.id());
    used_.erase(w.id());
  }

  /*************************************************************************
   * 查询当前被标记为“已使用”的寄存器集合
   *************************************************************************/
  std::set<uint32_t> getUsed() { return used_; }

private:
  void init() {
    for (uint32_t i = 0; i < 29; ++i) {
      if(i == 18) { continue; } // Platform Register
      free_.insert(i);
    }
    used_.clear();
  }

  void useOne(const GpX& rx) {
    used_.insert(rx.id());
    free_.erase(rx.id());
  }

  void useOne(const GpW& rw) {
    used_.insert(rw.id());
    free_.erase(rw.id());
  }

  std::set<uint32_t>::iterator nextFree() {
    return free_.begin();
  }

private:
  std::set<uint32_t> free_;
  std::set<uint32_t> used_;
};