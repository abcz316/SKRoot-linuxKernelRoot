#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include "capstone/capstone.h"

namespace a64_find_func_arg_size {

// 仅看“第一次有效读取”的宽度：Wn=4, Xn=8

static inline bool str_eq(const char* a, const char* b) {
	return a && b && std::strcmp(a, b) == 0;
}

static inline bool starts_with(const char* s, const char* prefix) {
	if (!s || !prefix) return false;
	while (*prefix) {
		if (*s == '\0' || *s != *prefix) return false;
		++s;
		++prefix;
	}
	return true;
}

static inline bool match_arg_reg(unsigned int reg, int arg_index, size_t& out_size) {
	if (arg_index < 0 || arg_index > 30) return false;
	if (reg == ARM64_REG_INVALID) return false;

	const unsigned int w = static_cast<unsigned int>(ARM64_REG_W0 + arg_index);
	const unsigned int x = static_cast<unsigned int>(ARM64_REG_X0 + arg_index);

	if (reg == w) {
		out_size = 4;
		return true;
	}
	if (reg == x) {
		out_size = 8;
		return true;
	}
	return false;
}

// ---------------------------
// 指令类别判断（尽量少而稳）
// ---------------------------

// op0 只写，不算“读”
static inline bool is_write_only_op0(const char* m) {
	return str_eq(m, "movn") ||
		str_eq(m, "movz") ||
		str_eq(m, "adr") ||
		str_eq(m, "adrp") ||
		str_eq(m, "mrs");   // mrs x0, sysreg : x0 是写
}

// op0 明确是“读”
static inline bool is_op0_read(const char* m) {
	return str_eq(m, "cmp") ||
		str_eq(m, "cmn") ||
		str_eq(m, "tst") ||
		str_eq(m, "cbz") ||
		str_eq(m, "cbnz") ||
		str_eq(m, "tbz") ||
		str_eq(m, "tbnz") ||
		str_eq(m, "br") ||
		str_eq(m, "blr") ||
		str_eq(m, "ret") ||
		str_eq(m, "movk"); // movk 读改写
}

// 所有 REG 操作数都按“读”处理（够用版）
static inline bool is_all_regs_read(const char* m) {
	// 普通 store / compare-test / branch-reg 这类
	if (is_op0_read(m)) return true;

	// 这些前缀绝大多数 REG 都是源寄存器
	// 但 stxr/stlxr/stxp/stlxp 例外，下面会单独处理
	if (starts_with(m, "str"))  return true;   // str/strb/strh...
	if (starts_with(m, "stur")) return true;   // stur/sturb/sturh...
	if (str_eq(m, "stp"))       return true;
	if (str_eq(m, "stnp"))      return true;
	if (starts_with(m, "sttr")) return true;   // sttr/sttrb/sttrh...
	if (str_eq(m, "msr"))       return true;   // msr sysreg, xN : xN 读

	// ccmp/ccmn 也属于读
	if (str_eq(m, "ccmp") || str_eq(m, "ccmn")) return true;

	return false;
}

// stxr/stlxr/stxrb/stlxrb/stxrh/stlxrh/stxp/stlxp
// 这类第 0 个 REG 是状态输出（写），后面的 REG 才是读
static inline bool is_store_exclusive_family(const char* m) {
	return str_eq(m, "stxr") ||
		str_eq(m, "stlxr") ||
		str_eq(m, "stxrb") ||
		str_eq(m, "stlxrb") ||
		str_eq(m, "stxrh") ||
		str_eq(m, "stlxrh") ||
		str_eq(m, "stxp") ||
		str_eq(m, "stlxp");
}

// ldp/ldnp/ldpsw/ldxp/ldaxp
// 这类前两个 REG 通常是写目的，不是读
static inline bool is_two_reg_dest_load_family(const char* m) {
	return str_eq(m, "ldp") ||
		str_eq(m, "ldnp") ||
		str_eq(m, "ldpsw") ||
		str_eq(m, "ldxp") ||
		str_eq(m, "ldaxp");
}

// cas/casal/casb/cash/casl/... 统一按 cas 前缀处理
// cas wOld, wNew, [xN] : op0 读写，op1 读，mem base 读
static inline bool is_cas_family(const char* m) {
	return starts_with(m, "cas");
}

// swp/swpa/swpal/... : op0 读, op1 写, mem 读
static inline bool is_swp_family(const char* m) {
	return starts_with(m, "swp");
}

// ldadd/ldclr/ldeor/ldset/ldsmax/ldsmin/ldumax/ldumin... : op0 读, op1 写, mem 读
static inline bool is_ld_atomic_rw_family(const char* m) {
	return starts_with(m, "ldadd") ||
		starts_with(m, "ldclr") ||
		starts_with(m, "ldeor") ||
		starts_with(m, "ldset") ||
		starts_with(m, "ldsmax") ||
		starts_with(m, "ldsmin") ||
		starts_with(m, "ldumax") ||
		starts_with(m, "ldumin");
}

// 某个 REG operand（按位置）是否算“读”
static inline bool reg_operand_is_read_semantic(const cs_insn* insn, uint8_t op_index) {
	const char* m = insn->mnemonic ? insn->mnemonic : "";

	// 1) 只写 op0
	if (is_write_only_op0(m)) {
		return op_index != 0;
	}

	// 2) 全 REG 读
	if (is_all_regs_read(m)) {
		return true;
	}

	// 3) store exclusive：op0 写，其他 REG 读
	if (is_store_exclusive_family(m)) {
		return op_index != 0;
	}

	// 4) cas：op0 读写，op1 读
	if (is_cas_family(m)) {
		return op_index == 0 || op_index == 1;
	}

	// 5) swp：op0 读，op1 写
	if (is_swp_family(m)) {
		return op_index == 0;
	}

	// 6) ldadd/ldclr/...：op0 读，op1 写
	if (is_ld_atomic_rw_family(m)) {
		return op_index == 0;
	}

	// 7) 双寄存器 load：前两个 REG 都是目的写入
	if (is_two_reg_dest_load_family(m)) {
		return op_index >= 2;
	}

	// 8) 普通 load：通常 op0 是目的写入
	//    注意：前面的原子 load 和双寄存器 load 已经拦过了
	if (starts_with(m, "ld")) {
		return op_index >= 1;
	}

	// 9) 默认按普通 ALU：op0 写，后面读
	//    例如 add x0, x1, x2 -> x1/x2 读
	//         add x0, x0, x2 -> 第 2 个操作数 x0 读
	return op_index != 0;
}

// 在单条指令里，找 arg 的“首次有效读取宽度”
static bool insn_first_read_arg_size(const cs_insn* insn, int arg_index, size_t& out_size) {
	if (!insn || !insn->detail) return false;

	const cs_arm64& a = insn->detail->arm64;

	// 按 operand 顺序扫描，尽量贴近“第一次读”
	for (uint8_t i = 0; i < a.op_count; ++i) {
		const cs_arm64_op& op = a.operands[i];

		// 1) 先处理 REG
		if (op.type == ARM64_OP_REG) {
			size_t reg_size = 0;
			if (!match_arg_reg(op.reg, arg_index, reg_size)) {
				continue;
			}

			if (reg_operand_is_read_semantic(insn, i)) {
				out_size = reg_size; // Wn=4, Xn=8
				return true;
			}

			// 只是写，不算“第一次有效读取”，继续往后看
			continue;
		}

		// 2) 再处理 MEM
		//    [base + index] 里的 base/index 都算读
		if (op.type == ARM64_OP_MEM) {
			size_t reg_size = 0;

			// base
			if (match_arg_reg(op.mem.base, arg_index, reg_size)) {
				out_size = reg_size; // 一般 base 是 Xn => 8
				return true;
			}

			// index
			if (match_arg_reg(op.mem.index, arg_index, reg_size)) {
				out_size = reg_size; // 可能是 Wn 或 Xn
				return true;
			}
		}
	}

	return false;
}

bool find_func_arg_size(const std::vector<char>& file_buf, size_t start, size_t end, int arg_index, size_t& out_size) {
	out_size = 0;

	if (start >= end) return false;
	if (end > file_buf.size()) return false;
	if (arg_index < 0 || arg_index > 30) return false;

	csh handle = 0;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
		return false;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	cs_insn* insn = cs_malloc(handle);
	if (!insn) {
		cs_close(&handle);
		return false;
	}

	const uint8_t* code = reinterpret_cast<const uint8_t*>(&file_buf[0]) + start;
	size_t code_size = end - start;   // 这里只扫 [start, end)
	uint64_t address = 0;

	bool found = false;

	while (cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
		size_t cur_size = 0;
		if (insn_first_read_arg_size(insn, arg_index, cur_size)) {
			out_size = cur_size;
			found = true;
			break;
		}
	}

	cs_free(insn, 1);
	cs_close(&handle);
	return found;
}

} // namespace a64_find_func_arg_size