#pragma once
#include <sys/syscall.h>
#include <sys/types.h>
#include <tuple>
#include <unordered_map>
#include <string_view>
#include <vector>
#include <set>
#include <string>
#include <type_traits>

#include "aarch64_asm_arg.h"
#include "aarch64_asm_idle_reg_pool.h"
#include "module_base_kernel_symbol_lookup.h"

/***************************************************************************
 * AArch64 内核API调用辅助类
 * 作用：
 *  - 封装“按符号名调用内核API”的完整流程：
 *      · 通过 kallsyms_lookup_name 解析符号地址；
 *      · 按 AAPCS64 规则将 Arm64Arg 参数打包到 x0～x7 / w0～w7；
 *      · 使用 BLR 生成实际调用指令序列。
 *
 *  - 自动处理寄存器使用与保护：
 *      · 根据 AAPCS64 保护规则生成需保护的 X 寄存器集合；
 *      · 结合 RegProtectGuard 插入保存/恢复指令，保护调用现场；
 *      · 借助 IdleRegPool 申请空闲通用寄存器，将“旧寄存器参数”搬运到“新临时寄存器”，避免 clobber 当前在用的寄存器。
 *
 *  - 提供多种调用方式：
 *      · 直接传入 std::vector<Arm64Arg> 作为参数向量；
 *      · 支持可变参数形式，内部通过 mk_args(...) 自动打包；
 *      · 支持一组候选符号名（不同内核版本符号差异），带线程本地缓存，
 *        优先重用上次成功的符号，减少 kallsyms 查找失败开销。
 *
 * 典型使用场景：
 *  - 在 Skroot 内核模块中，需要安全地按符号名调用某个内核函数，
 *    又不想在每个调用点手写一大段寄存器保护 + 装参 + BLR 的重复代码时，
 *    可以通过本类提供的静态接口直接生成完整调用序列。
 ***************************************************************************/
class Aarch64KernelSymCallHelper {
public:
  using Asm    = asmjit::a64::Assembler;
  using ArgVec = std::vector<Arm64Arg>;
  
	/*************************************************************************
	 * 枚举 NeedReturnX0
	 * 作用: 是否保留被调用函数的 x0 返回值
	 *************************************************************************/
	enum class NeedReturnX0 : bool { No = false, Yes = true };
  using NeedReturnX0 = Aarch64KernelSymCallHelper::NeedReturnX0;

  /***************************************************************************
   * 自动保护 caller-saved 寄存器 + 申请临时寄存器 + 搬运旧寄存器，最终按符号名调用。
   * 参数：a        : Assembler 指针
   *      sym_name : 内核符号名
   *      need_x0  : 是否保留被调用函数的 x0 返回值
   *      args     : 原始参数向量
   **************************************************************************/
  static KModErr callNameAuto(Asm* a,
                              const char* sym_name,
                              NeedReturnX0 need_x0,
                              const ArgVec& args) {
    // 1) 根据 AAPCS64 规则构建保护寄存器集合
    std::set<uint32_t> protect_ids = makeProtectSet(AAPCS64_ProtectRule::CallerSaved);
    if(need_x0 == NeedReturnX0::Yes) {
      protect_ids = excluding_x0(protect_ids);
    }
    RegProtectGuard guard(a, protect_ids);

    // 2) 建立“空闲寄存器池”，把当前参数里用到的寄存器标记为已占用
    ArgVec args_ditry = makeDirtyArgsX0ToX7(args);
    IdleRegPool pool = IdleRegPool::makeFromVec(args_ditry);

    // 3) 为每个寄存器参数分配新的临时寄存器，并插入 mov 从“旧寄存器”搬运到“新寄存器”
    ArgVec new_regs = acquireNewArgRegs(pool, args);
    emitMovesFromOldToNew(a, new_regs, args);

    // 4) 使用重映射后的参数向量进行调用
    return call_by_name_raw(a, sym_name, new_regs);
  }

  // 防止与 ArgVec 重载产生二义性：如果参数包里已经包含 ArgVec，则不参与该模板重载
  template <class T>
  using is_ArgVec = std::is_same<std::decay_t<T>, ArgVec>;

  /**
   * 便捷重载：接受任意 Arm64Arg 可构造参数（例如 X(x0), W(w1), Imm64(...) 等），
   * 内部通过 mk_args(...) 组装为 ArgVec，再走上面的主流程。
   */
  template <
      typename... Args,
      std::enable_if_t<!std::disjunction_v<is_ArgVec<Args>...>, int> = 0>
  static KModErr callNameAuto(Asm* a,
                              const char* sym_name,
                              NeedReturnX0 need_x0,
                              Args&&... args) {
    ArgVec orig = mk_args(std::forward<Args>(args)...);
    return callNameAuto(a, sym_name, need_x0, orig);
  }

  /***************************************************************************
   * 在候选符号列表中寻找可用符号并调用（兼容不同内核版本）
   * 参数：candidates: 一个或多个候选符号名
   *      err     : 输出错误码
   *      need_x0 : 是否保留被调用函数的 x0 返回值
   *      args... : 调用参数（同上，可是 ArgVec 或表达式参数）。
   *
   * 逻辑：
   *  1) 根据 candidates 计算一个 hash key，在线程本地缓存中查找“上一次成功的符号名”；
   *  2) 先试缓存命中的符号名，如果存在且调用成功，直接返回；
   *  3) 否则遍历 candidates，只要不是“符号不存在”的错误，就把该错误返回并缓存；
   *  4) 如果所有候选都不存在，则返回 ERR_MODULE_SYMBOL_NOT_EXIST。
   **************************************************************************/
  template <typename... Args>
  static void callSymbolCandidates(
      Asm* a,
      KModErr& err,
      const std::vector<std::string>& candidates,
      NeedReturnX0 need_x0,
      Args&&... args) {
    using CacheMap = std::unordered_map<size_t, std::string>;
    static thread_local CacheMap s_last_ok;

    // 把可变参收进 tuple，lambda 中再展开
    auto args_tpl = std::make_tuple(std::forward<Args>(args)...);

    // 生成 hash key：对所有候选符号名做 hash_combine
    auto hash_combine = [](size_t& seed, size_t v) {
      seed ^= v + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    };
    size_t key = 0;
    std::hash<std::string_view> h;
    for (const auto& sym : candidates) {
      hash_combine(key, h(std::string_view(sym)));
    }

    // 实际执行调用的 lambda：展开 tuple 调用 callNameAuto(...)
    auto do_call = [&](const char* sym) -> KModErr {
      return std::apply(
          [&](auto&&... xs) {
            return callNameAuto(a, sym, need_x0, std::forward<decltype(xs)>(xs)...);
          },
          args_tpl);
    };

    // 1) 优先尝试缓存中的符号名
    if (auto it = s_last_ok.find(key); it != s_last_ok.end()) {
      err = do_call(it->second.c_str());
      if (is_ok(err)) return;
      if (err != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) return; // 其它错误，直接返回
      s_last_ok.erase(it);                                     // 符号已不存在，清缓存
    }

    // 2) 遍历候选符号名
    for (const auto& sym : candidates) {
      err = do_call(sym.c_str());
      if (is_ok(err)) {
        s_last_ok[key] = sym;  // 记录本次成功的符号名，便于下次直达
        return;
      }
      if (err != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) {
        // 符号存在但调用出错，也缓存起来，避免下次重复遍历
        s_last_ok[key] = sym;
        return;
      }
    }

    // 3) 所有候选符号都不存在
    err = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
  }

private:
  // AAPCS64 下的寄存器保护规则
  enum class AAPCS64_ProtectRule {
    CallerSaved,
    CalleeSaved,
    AllABI,
  };

  /***************************************************************************
   * 根据 AAPCS64 规则构建需要保护的 X 寄存器集合
   * 参数：CallerSaved : 保护 x0～x17（x18 为平台寄存器，不在此范围内）
   *    CalleeSaved : 保护 x19～x28 以及 x29(FP)
   *    AllABI      : 等价于 CallerSaved ∪ CalleeSaved。
   *
   * 典型用法：将返回的集合直接传入 RegProtectGuard，用于统一插入保存 / 恢复指令，保护调用现场寄存器。
   **************************************************************************/
  static std::set<uint32_t> makeProtectSet(AAPCS64_ProtectRule rule) {
    std::set<uint32_t> s;
    switch (rule) {
      case AAPCS64_ProtectRule::CallerSaved:
        for (uint32_t i = 0; i <= 17; ++i) s.insert(i);
        // x18 为平台寄存器，不自动加入
        break;

      case AAPCS64_ProtectRule::CalleeSaved:
        for (uint32_t i = 19; i <= 28; ++i) s.insert(i);
        s.insert(29); // FP
        break;

      case AAPCS64_ProtectRule::AllABI:
        s = makeProtectSet(AAPCS64_ProtectRule::CallerSaved);
        {
          auto callee = makeProtectSet(AAPCS64_ProtectRule::CalleeSaved);
          s.insert(callee.begin(), callee.end());
        }
        break;
    }
    return s;
  }

  // 仅用于 IdleRegPool 建池：强制把 x0～x7 也视为“已占用”
  // 目的：避免池把参数寄存器(x0～x7/w0～w7)分配给临时寄存器，导致后续装参/搬运阶段互相踩寄存器。
  static ArgVec makeDirtyArgsX0ToX7(const ArgVec& args) {
    bool seen[8] = {}; // seen[i] 表示 args 中是否已经出现过 x{i}/w{i}

    for (const auto& a : args) {
      uint32_t id = 0;
      switch (a.kind) {
        case Arm64ArgKind::XReg:
          id = static_cast<uint32_t>(a.x.id());
          if (id < 8) seen[id] = true;
          break;
        case Arm64ArgKind::WReg:
          id = static_cast<uint32_t>(a.w.id());
          if (id < 8) seen[id] = true;
          break;
        case Arm64ArgKind::Imm64:
        case Arm64ArgKind::Imm32:
          break;
      }
    }

    ArgVec out = args;
    out.reserve(args.size() + 8);
    for (uint32_t i = 0; i < 8; ++i) {
      if (!seen[i]) {
        // 注意：这里只是为了“占坑/保留”，不会用于真实 call 的装参，因为真实调用仍用原始 args
        out.emplace_back(Arm64Arg::X(asmjit::a64::x(i)));
      }
    }
    return out;
  }

  /***************************************************************************
   * 从 IdleRegPool 中申请新的临时寄存器，并基于旧参数生成新的参数向量。
   **************************************************************************/
  static ArgVec acquireNewArgRegs(IdleRegPool& pool, const ArgVec& in) {
    ArgVec out;
    out.reserve(in.size());
    for (auto& a : in) {
      switch (a.kind) {
        case Arm64ArgKind::XReg: {
          auto nx = pool.acquireX();
          out.emplace_back(Arm64Arg::X(nx));
          break;
        }
        case Arm64ArgKind::WReg: {
          auto nw = pool.acquireW();
          out.emplace_back(Arm64Arg::W(nw));
          break;
        }
        case Arm64ArgKind::Imm64:
        case Arm64ArgKind::Imm32:
          out.emplace_back(a);
          break;
      }
    }
    return out;
  }

  
  /***************************************************************************
   * 把“旧寄存器参数”的值搬运到“新寄存器参数”中。
   **************************************************************************/
  static void emitMovesFromOldToNew(Asm* a, const ArgVec& new_regs, const ArgVec& old_regs) {
    const size_t n = std::min(new_regs.size(), old_regs.size());
    for (size_t i = 0; i < n; ++i) {
      const auto& nr = new_regs[i];
      const auto& orr = old_regs[i];
      if (nr.kind == Arm64ArgKind::XReg && orr.kind == Arm64ArgKind::XReg) {
        a->mov(nr.x, orr.x);
      } else if (nr.kind == Arm64ArgKind::WReg && orr.kind == Arm64ArgKind::WReg) {
        a->mov(nr.w, orr.w);
      } else {
        // 立即数 / 跨宽度场景：由装参阶段根据 kind 重新装入即可，这里不插 mov
      }
    }
  }
  
  /***************************************************************************
   * 将参数向量按 AAPCS64 规则放入 x0～x7 / w0～w7。
   **************************************************************************/
  static bool pushArgsFromVec(Asm* a, const ArgVec& args) {
    const size_t n = args.size(); 
    if(n > 8) return false; // AArch64 前8个参数寄存器
    for (size_t i = 0; i < n; ++i) {
      const auto& arg = args[i];
      switch (arg.kind) {
        case Arm64ArgKind::XReg:
          a->mov(asmjit::a64::x(i), arg.x);
          break;
        case Arm64ArgKind::WReg:
          a->mov(asmjit::a64::w(i), arg.w);
          break;
        case Arm64ArgKind::Imm64:
          aarch64_asm_mov_x(a, asmjit::a64::x(i), arg.imm64);
          break;
        case Arm64ArgKind::Imm32:
          aarch64_asm_mov_w(a, asmjit::a64::w(i), arg.imm32);
          break;
      }
    }
    return true;
  }

  /***************************************************************************
   * 通过 kallsyms_lookup_name 查找符号地址并调用（不做寄存器重映射）。
   *
   * 注意：
   *  - 不负责保护任何寄存器，只负责装参 + BLR；
   *  - 调用前需要外部已经做好 RegProtectGuard 等保护；
   *  - args 中的寄存器会被直接用作参数寄存器的来源。
   **************************************************************************/
  static KModErr call_by_name_raw(Asm* a, const char* sym_name, const ArgVec& args) {
    uint64_t target = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name(sym_name, target));

    // 按 AAPCS64 规则把参数放入 x0～x7 / w0～w7
    if(!pushArgsFromVec(a, args)) return KModErr::ERR_MODULE_SYMBOL_PARAM;

    // 使用 x11 作跳板寄存器
    {
      RegProtectGuard g1(a, asmjit::a64::x(11));
      aarch64_asm_mov_x(a, asmjit::a64::x(11), target);
      aarch64_asm_safe_blr(a, asmjit::a64::x(11));
    }
    return KModErr::OK;
  }

};
