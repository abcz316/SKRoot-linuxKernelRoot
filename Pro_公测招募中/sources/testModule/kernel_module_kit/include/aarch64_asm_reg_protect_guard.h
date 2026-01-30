#pragma once
#include <set>
#include <type_traits>
#include <algorithm>
#include <cstdio>
#include "kernel_module_kit_umbrella.h"

/***************************************************************************
 * AArch64 寄存器保护守卫类
 * 作用: 自动生成寄存器保存/恢复指令（stp/ldp），用于保护现场，作用域结束自动恢复现场。
 *
 * 用法示例：
 * {
 *   // Guard 作用域：这里可随意改寄存器，离开作用域后自动恢复现场
 *   RegProtectGuard g1(a, x0, x1, x2);
 *   a->mov(x0, Imm(1));
 *   a->mov(x1, Imm(2));
 *   a->mov(x2, Imm(3));
 * }
 ***************************************************************************/
class RegProtectGuard {
	using GpX = asmjit::a64::GpX;
	using GpW = asmjit::a64::GpW;
public:
	/*************************************************************************
	 * 构造函数模板 (支持任意数量 X/W 寄存器)
	 * 参数: a		: asmjit::a64::Assembler 指针
	 *   	regs	: 可变参数列表（GpX/GpW）
	 * 逻辑:
	 *   	1. 生成 stp 指令序列 (push pairs)；
	 *   	2. 析构时自动生成对应 ldp 指令 (pop pairs)。
	 *************************************************************************/
	template <typename... Regs,
			typename = std::enable_if_t<(std::conjunction_v<
				std::bool_constant<std::is_same_v<std::decay_t<Regs>, GpX> ||
									std::is_same_v<std::decay_t<Regs>, GpW>>...
			>)>>
	explicit RegProtectGuard(asmjit::a64::Assembler* a, const Regs&... regs)
		: a_(a) {
		regs_.reserve(sizeof...(regs) + 1);
		(appendOneUnique(regs), ...);
		if (regs_.empty()) return;
		if (regs_.size() & 1) regs_.push_back(xzr);
		doPushPairs();
		pushed_ = true;
	}

	/*************************************************************************
	 * 构造函数（根据寄存器编号集合构造）
	 * 参数: a		: Assembler 指针
	 *		regs_id	: 需要保护的寄存器编号集合（0 表示 x0，1 表示 x1，...）。
	 *
	 * 逻辑:
	 *   1. 将每个编号转换为 GpX (x(id)) 并去重加入 regs_；
	 *   2. 若数量为奇数，则补一个 xzr；
	 *   3. 发出 stp 指令对，将这些寄存器压栈；
	 *   4. 析构时再自动弹栈恢复。
	 *************************************************************************/
	explicit RegProtectGuard(asmjit::a64::Assembler* a, const std::set<uint32_t>& regs_id)
		: a_(a) {
		regs_.reserve(regs_id.size() + 1);
		for(auto id : regs_id) {
			appendOneUnique(asmjit::a64::x(id));
		}
		if (regs_.empty()) return;
		if (regs_.size() & 1) regs_.push_back(xzr);
		doPushPairs();
		pushed_ = true;
	}

	// DO NOT COPY && DO NOT DELETE
	RegProtectGuard(const RegProtectGuard&) = delete;
	RegProtectGuard& operator=(const RegProtectGuard&) = delete;
	RegProtectGuard(RegProtectGuard&& other) noexcept
		: a_(other.a_), regs_(std::move(other.regs_)), pushed_(other.pushed_) {
		other.pushed_ = false;
	}
	RegProtectGuard& operator=(RegProtectGuard&& other) noexcept {
		if (this != &other) {
			cleanup();
			a_ = other.a_;
			regs_ = std::move(other.regs_);
			pushed_ = other.pushed_;
			other.pushed_ = false;
		}
		return *this;
	}

	~RegProtectGuard() { cleanup(); }

private:
	static GpX toX(const GpX& rx) { return rx; }
	static GpX toX(const GpW& rw) { return asmjit::a64::x(rw.id()); }

	void appendOneUnique(const GpX& r) {
		const uint32_t id = r.id();
		for (auto &v : regs_) if (v.id() == id) return;
		regs_.push_back(r);
	}
	void appendOneUnique(const GpW& r) { appendOneUnique(asmjit::a64::x(r.id())); }

	void doPushPairs() {
		for (size_t i = 0; i < regs_.size(); i += 2) {
			GpX a1 = regs_[i];
			GpX a2 = regs_[i + 1];
			if(a1 == xzr && a2 == xzr) continue;
			a_->stp(a1, a2, ptr(sp).pre(-16));
		}
	}

	void doPopPairs() {
		for (size_t i = regs_.size(); i > 0; i -= 2) {
			GpX a1 = regs_[i - 2];
			GpX a2 = regs_[i - 1];
			if(a1 == xzr && a2 == xzr) continue;
			a_->ldp(a1, a2, ptr(sp).post(16));
		}
	}

	void cleanup() {
		if (!pushed_ || !a_) return;
		doPopPairs();
		pushed_ = false;
		regs_.clear();
	}

private:
	asmjit::a64::Assembler* a_ = nullptr;
	std::vector<GpX> regs_;
	bool pushed_ = false;

	const GpX xzr = asmjit::a64::xzr;
	const GpX sp = asmjit::a64::sp;
};

// 从输入的寄存器号集合中移除 X0（编号 0）
static std::set<uint32_t> excluding_x0(std::set<uint32_t> reg_ids) {
    reg_ids.erase(uint32_t{0});
    return reg_ids;
}