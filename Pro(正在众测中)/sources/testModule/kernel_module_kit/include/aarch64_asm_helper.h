#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>

#define ASMJIT_STATIC
#include "asmjit2/core.h"
#include "asmjit2/a64.h"
namespace {
using namespace asmjit;
using namespace asmjit::a64;

/********************************************************************
 * AArch64 / AsmJit 辅助工具集
 * 作用：
 *   - 对 AsmJit 的基础能力做一层轻量封装，便于在任意环境下快速生成
 *     AArch64 指令序列、转换为字节流，并补充若干常用的“裸指令编码”。
 ********************************************************************/

/******************************************************************
 * AsmJit 错误处理器：将错误输出到 stderr
 ******************************************************************/
class MyAsmJitErrorHandler : public ErrorHandler {
public:
	void handleError(Error err, const char* message, BaseEmitter* origin) override {
		std::cerr << "[发生错误] " << DebugUtils::errorAsString(err) << ": " << message << std::endl;
		isErr = true;
	}

	// 查询是否曾经发生过错误。
	bool isError() { return isErr; }
private:
	bool isErr = false;
};

/******************************************************************
 * AArch64 汇编上下文
 *   - assembler() : 获取 AArch64 Assembler 指针
 *   - has_error() : 查询是否发生过 AsmJit 错误
 ******************************************************************/
struct aarch64_asm_ctx {
public:
	Assembler* assembler() noexcept { return a_.get(); }
	bool has_error() const noexcept { return err_ && err_->isError(); }
private:
	std::unique_ptr<StringLogger>      logger_;
	std::unique_ptr<CodeHolder>        codeHolder_;
	std::unique_ptr<MyAsmJitErrorHandler>      err_;
	std::unique_ptr<Assembler>    a_;
	friend aarch64_asm_ctx init_aarch64_asm();
};

/******************************************************************
 * 初始化一个独立的 AArch64 汇编环境
 ******************************************************************/
aarch64_asm_ctx init_aarch64_asm() {
	aarch64_asm_ctx ctx;
	Environment env(Arch::kAArch64);
	ctx.codeHolder_ = std::make_unique<CodeHolder>();
	ctx.codeHolder_->init(env);
	ctx.logger_ = std::make_unique<StringLogger>();
	ctx.logger_->addFlags(FormatFlags::kNone);
	ctx.codeHolder_->setLogger(ctx.logger_.get());
	ctx.err_ = std::make_unique<MyAsmJitErrorHandler>();
	ctx.a_ = std::make_unique<Assembler>(ctx.codeHolder_.get());
	ctx.a_->setErrorHandler(ctx.err_.get());
	return ctx;
}

/******************************************************************
 * 将 AArch64 汇编机器码导出为字节数组
 ******************************************************************/
std::vector<uint8_t> aarch64_asm_to_bytes(const Assembler* a) {
	if (!a) return {};
	auto* err_handler = a->errorHandler();
	if (!err_handler) return {};
	auto* my_err_handler = static_cast<MyAsmJitErrorHandler*>(err_handler);
	if (my_err_handler->isError()) return {};
	CodeHolder* code = a->code();
	if (!code) return {};
	Section* sec = code->sectionById(0);
	if (!sec) return {};
	const CodeBuffer& buf = sec->buffer();
	return { buf.data(), buf.data() + buf.size() };
}

/******************************************************************
 * 生成一条 B 指令（相对 PC 跳转）
 * 参数：a       : Assembler 指针；
 * 		b_value : 以字节为单位的跳转偏移（从当前 PC 起算），必须为 4 的倍数，且偏移范围必须在 ±128MB 之内。
 * 返回：true 表示成功; false 表示失败。
 ******************************************************************/
bool aarch64_asm_b(Assembler* a, int32_t b_value) {
	if (b_value % 4 != 0) {
		std::cout << "[发生错误] The B instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	int64_t imm26 = b_value >> 2;
	if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
		std::cout << "[发生错误] B instruction offset exceeds ± 128MB range" << std::endl;
		return false;
	}
	int32_t offset = b_value >> 2;
	uint32_t instr = 0x14000000 | (offset & 0x03FFFFFF);
	a->embed((const uint8_t*)&instr, sizeof(instr));
	return true;
}

/******************************************************************
 * 生成一条 BL 指令（相对 PC 跳转）
 * 参数：a       : Assembler 指针；
 * 		bl_value : 以字节为单位的跳转偏移（从当前 PC 起算），必须为 4 的倍数，且偏移范围必须在 ±128MB 之内。
 * 返回：true 表示成功; false 表示失败。
 ******************************************************************/
bool aarch64_asm_bl_raw(Assembler* a, int32_t bl_value) {
	if (bl_value % 4 != 0) {
		std::cout << "[发生错误] The BL instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	int64_t imm26 = bl_value >> 2;
	if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
		std::cout << "[发生错误] BL instruction offset exceeds ±128MB range" << std::endl;
		return false;
	}
	int32_t offset26 = bl_value >> 2;
	uint32_t instr = 0x94000000u | (static_cast<uint32_t>(offset26) & 0x03FFFFFFu);
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
	return true;
}

/******************************************************************
 * 安全版本的 BL（在调用前后保护 x29 / x30，避免破坏调用者栈帧)。
 * 序列：
 *   stp x29, x30, [sp, #-16]!
 *   bl  label
 *   ldp x29, x30, [sp], #16
 *****************************************************************/
void aarch64_asm_safe_bl(Assembler* a, Label label) {
	a->stp(x29, x30, ptr(sp).pre(-16));
	a->bl(label);
	a->ldp(x29, x30, ptr(sp).post(16));
}

/******************************************************************
 * 安全版本的 BLR（在调用前后保护 x29 / x30，避免破坏调用者栈帧)。
 * 序列：
 *   stp x29, x30, [sp, #-16]!
 *   blr x
 *   ldp x29, x30, [sp], #16
 *****************************************************************/
void aarch64_asm_safe_blr(Assembler* a, GpX x) {
	a->stp(x29, x30, ptr(sp).pre(-16));
	a->blr(x);
	a->ldp(x29, x30, ptr(sp).post(16));
}

/******************************************************************
 * 手工生成一条 ADR 指令
 * 通过在临时 CodeHolder 中构造一小段代码，计算并拷贝出 ADR 指令编码，再 embed 到目标 Assembler 中。
 * 参数：a       : Assembler 指针
 * 		x         : 目标 X 寄存器
 * 		adr_value : 字节偏移（以 4 对齐），范围 ±1MB。
 * 注意：这里采用 “临时汇编 + 抽取指令” 的方式，实际效果是等价于在当前 PC 附近生成一条 ADR x, label。
 *****************************************************************/
bool aarch64_asm_adr_x(Assembler* a, GpX x, int32_t adr_value) {
	if (!a) return false;
	if (adr_value % 4 != 0) {
		std::cout << "[发生错误] The ADR instruction offset must be a multiple of 4" << std::endl;
		return false;
	}
	// ADR 立即数范围：±1MB（字节范围）
	if (adr_value < -(1 << 20) || adr_value >((1 << 20) - 1)) {
		std::cout << "[发生错误] ADR instruction offset exceeds ± 1MB range" << std::endl;
		return false;
	}
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	Assembler* a2 = asm_ctx.assembler();
	if (!a2) return false;
	Label label_start = a2->newLabel();
	const int32_t size = std::abs(adr_value);
	std::vector<uint8_t> filler(static_cast<size_t>(size), 0x00);
	if (adr_value > 0) {
		a2->adr(x, label_start);
		if (size) a2->embed(filler.data(), filler.size());
		a2->bind(label_start);
		a2->nop();
	} else {
		a2->bind(label_start);
		if (size) a2->embed(filler.data(), filler.size());
		a2->adr(x, label_start);
	}
	auto bytes = aarch64_asm_to_bytes(a2);
	if (bytes.empty()) return false;
	const size_t adr_off = (adr_value < 0) ? static_cast<size_t>(size) : 0;
	if (bytes.size() < adr_off + 4) return false;
	a->embed(bytes.data() + adr_off, 4);
	return true;
}

/******************************************************************
 * 将一个 64bit 常量赋值 X 寄存器：
 * 参数：a		: Assembler 指针
 * 		x         : 目标 X 寄存器
 * 		value	 : 64bit 常量
 *****************************************************************/
void aarch64_asm_mov_x(Assembler* a, GpX x, uint64_t value) {
	bool isInitialized = false;
	for (int idx = 0; idx < 4; ++idx) {
		uint16_t imm16 = (value >> (idx * 16)) & 0xFFFF;
		if (imm16 == 0) continue;
		if (!isInitialized) {
			a->movz(x, imm16, idx * 16);
			isInitialized = true;
		} else {
			a->movk(x, imm16, idx * 16);
		}
	}
	if (!isInitialized) {
		a->movz(x, 0, 0);
	}
}

/******************************************************************
 * 将一个 32bit 常量赋值到 W 寄存器
 * 参数：a		: Assembler 指针；
 * 		x        : 目标 W 寄存器
 * 		value	 : 32bit 常量
 *****************************************************************/
void aarch64_asm_mov_w(Assembler* a, GpW w, uint32_t value) {
	bool isInitialized = false;
	for (int idx = 0; idx < 2; ++idx) {
		uint16_t imm16 = (value >> (idx * 16)) & 0xFFFF;
		if (imm16 == 0) continue;
		if (!isInitialized) {
			a->movz(w, imm16, idx * 16);
			isInitialized = true;
		} else {
			a->movk(w, imm16, idx * 16);
		}
	}
	if (!isInitialized) {
		a->movz(w, 0, 0);
	}
}

/******************************************************************
 * 在当前代码后方嵌入一块数据，并让 x 指向它
 * 参数：a		: Assembler 指针
 * 		x		: 目标 X 寄存器
 * 		data	: 数据集
 *****************************************************************/
void aarch64_asm_set_x_data_ptr(Assembler* a, GpX x, const std::vector<uint8_t>& data) {
	auto align_up4 = [](size_t v) -> size_t { return (v + 3) & ~size_t(3); };
	const size_t n_raw = data.size();
	const size_t n_padded = align_up4(n_raw);
	std::vector<uint8_t> buf(n_padded, 0u);
	if (!data.empty()) memcpy(buf.data(), data.data(), data.size());
	Label label_entry = a->newLabel();
	a->b(label_entry);
	int off_addr_start = a->offset();
	a->embed(buf.data(), buf.size());
	a->bind(label_entry);
	const int off = off_addr_start - a->offset();
	aarch64_asm_adr_x(a, x, off);
}

/******************************************************************
 * 在代码中嵌入一个 C 字符串常量，并让 x 指向它
 * 参数：a		: Assembler 指针
 * 		x		: 目标 X 寄存器
 * 		data	: 字符串常量
 *****************************************************************/
void aarch64_asm_set_x_cstr_ptr(Assembler* a, GpX x, const std::string& str) {
	std::vector<uint8_t> buf(str.size() + 1, 0u);
	if (!str.empty()) memcpy(buf.data(), str.c_str(), str.size());
	aarch64_asm_set_x_data_ptr(a, x, buf);
}

/******************************************************************
 * BTI C
 *****************************************************************/
void aarch64_asm_bit_c(Assembler* a) {
	uint32_t instr = 0xD503245F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * BTI J
 *****************************************************************/
void aarch64_asm_bit_j(Assembler* a) {
	uint32_t instr = 0xD503249F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * BTI JC
 *****************************************************************/
void aarch64_asm_bit_jc(Assembler* a) {
	uint32_t instr = 0xD50324DF;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * PACIA Xn
 *****************************************************************/
void aarch64_asm_pacia(Assembler* a, GpX x) {
	uint32_t instr = 0xDAC103E0 | x.id();
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * PACIASP
 *****************************************************************/
void aarch64_asm_paciasp(Assembler* a) {
	uint32_t instr = 0xD503233F;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * AUTIASP
 *****************************************************************/
void aarch64_asm_autiasp(Assembler* a) {
	uint32_t instr = 0xD50323BF;
	a->embed(reinterpret_cast<const uint8_t*>(&instr), sizeof(instr));
}

/******************************************************************
 * 生成一条 MRS 指令，将 ID_AA64MMFR0_EL1 读入指定 X 寄存器。
 *****************************************************************/
void aarch64_asm_mrs_id_aa64mmfr0_el1(Assembler* a, GpX x) {
	a->mrs(x, Predicate::SysReg::encode(3, 0, 0, 7, 0));
}

/******************************************************************
 * 生成一条 MRS 指令，将 TCR_EL1 读入指定 X 寄存器。
 *****************************************************************/
void aarch64_asm_mrs_tcr_el1(Assembler* a, GpX x) {
    a->mrs(x, Predicate::SysReg::encode(3, 0, 2, 0, 2));
}

/******************************************************************
 * 生成一条 MRS 指令，将 TTBR0_EL1 读入指定 X 寄存器。
 *****************************************************************/
void aarch64_asm_mrs_ttbr0_el1(Assembler* a, GpX x) {
    a->mrs(x, Predicate::SysReg::encode(3, 0, 2, 0, 0));
}

/******************************************************************
 * 生成一条 MRS 指令，将 CTR_EL0 读入指定 X 寄存器。
 *****************************************************************/
void aarch64_asm_mrs_ctr_el0(Assembler* a, GpX x) {
	a->mrs(x, Predicate::SysReg::encode(3, 3, 0, 0, 1));
}

/******************************************************************
 * 生成一条 MRS 指令，将 DAIF 读入指定 X 寄存器。
 *****************************************************************/
void aarch64_asm_mrs_daif(Assembler* a, GpX x) {
    a->mrs(x, Predicate::SysReg::encode(3, 3, 4, 2, 1));
}

/******************************************************************
 * 生成一条 MSR 指令，写入 DAIF 指定值。
 *****************************************************************/
void aarch64_asm_msr_daif(Assembler* a, GpX x) {
    a->msr(Predicate::SysReg::encode(3, 3, 4, 2, 1), x);
}

/******************************************************************
 * 生成一条 MSR 指令，写入 DAIFSet 指定值。
 *****************************************************************/
void aarch64_asm_msr_daifset(Assembler* a, uint32_t imm4) {
    a->msr(Imm(Predicate::PState::encode(3, 6)), Imm(imm4));
}

/******************************************************************
 * 生成一条 DC CVAC, Xn 指令
 *****************************************************************/
void aarch64_asm_dc_cvac(Assembler* a, GpX x) {
	a->dc(Imm(Predicate::DC::encode(3, 7, 10, 1)), x);
}

/******************************************************************
 * IC IALLU
 ******************************************************************/
void aarch64_asm_ic_iallu(Assembler* a) {
	a->ic(Imm(Predicate::IC::encode(0, 7, 5, 0)), xzr);
}

/******************************************************************
 * DSB ISH
 *****************************************************************/
void aarch64_asm_dsb_ish(Assembler* a) {
	a->dsb(Imm(Predicate::DB::kISH));
}

/******************************************************************
 * ISB
 *****************************************************************/
void aarch64_asm_isb(Assembler* a) {
	a->isb(Imm(Predicate::ISB::kSY));
}

/******************************************************************
 * AT S1E1R, Xn
 *****************************************************************/
void aarch64_asm_at_s1e1r(Assembler* a, GpX virtReg) {
    a->at(Imm(Predicate::AT::encode(0, 7, 8, 0)), virtReg);
}

/******************************************************************
 * MRS Xn, PAR_EL1
 *****************************************************************/
void aarch64_asm_mrs_par_el1(Assembler* a, GpX x) {
    a->mrs(x, Imm(Predicate::SysReg::encode(3, 0, 7, 4, 0)));
}

/******************************************************************
 * 打印 AsmJit 生成的 AArch64 汇编文本（大写）
 *****************************************************************/
std::string print_aarch64_asm(Assembler* a) {
	if (!a) return {};
	CodeHolder* code = a->code();
	if (!code) return {};
	Logger* logger = code->logger();
	if (!logger) return {};
	auto* str_logger = static_cast<StringLogger*>(logger);
	std::string text = str_logger->data();
	transform(text.begin(), text.end(), text.begin(), ::toupper);
	return text;
}

}