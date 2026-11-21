#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <string>
#include <cstdint>
#include "capstone/capstone.h"

namespace a64_find_imm_register_offset {

struct code_line {
	uint64_t addr = 0;
	arm64_insn cmd_id = ARM64_INS_INVALID;
	int64_t mem_disp = 0;
	int64_t imm[2] = {0, 0};
};

inline bool is_control_flow(csh handle, const cs_insn* insn) {
	return cs_insn_group(handle, insn, CS_GRP_JUMP) || cs_insn_group(handle, insn, CS_GRP_CALL) || cs_insn_group(handle, insn, CS_GRP_RET);
}

inline void handle_candidate_offsets(const std::vector<code_line>& v_code_line,
                                     std::vector<int64_t>& candidate_offsets) {
	for (size_t x = 0; x < v_code_line.size(); x++) {
		const auto& line = v_code_line[x];

		if (line.mem_disp > 0) candidate_offsets.push_back(line.mem_disp);
		if (line.imm[0] > 0) candidate_offsets.push_back(line.imm[0]);
		if (line.imm[1] > 0) candidate_offsets.push_back(line.imm[1]);
	}
}

inline bool find_imm_register_offset(const std::vector<char>& file_buf, size_t start, size_t end, std::vector<int64_t>& candidate_offsets) {
	candidate_offsets.clear();
	if (start >= end || end > file_buf.size()) return false;
	if ((start % 4) != 0) return false;
	if (((end - start) % 4) != 0) return false;

	size_t total_code_size = end - start;
	size_t remaining_size = total_code_size;

	csh handle;
	cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	if (err != CS_ERR_OK) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		return false;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

	cs_insn* insn = cs_malloc(handle);
	if (!insn) {
		cs_close(&handle);
		return false;
	}

	uint64_t address = 0;
	const uint8_t* code = reinterpret_cast<const uint8_t*>(file_buf.data()) + start;

	std::vector<code_line> v_code_line;
	v_code_line.reserve(total_code_size / 4);

	while (cs_disasm_iter(handle, &code, &remaining_size, &address, insn)) {
		// 排除 BL、B、CBZ、CBNZ、TBZ、TBNZ 等控制流指令
		if (is_control_flow(handle, insn)) continue;

		code_line line;
		line.addr = insn->address;
		line.cmd_id = static_cast<arm64_insn>(insn->id);

		int idx = 0;
		for (uint8_t y = 0; y < insn->detail->arm64.op_count; y++) {
			const auto& op = insn->detail->arm64.operands[y];
			if (op.type == ARM64_OP_IMM) {
				if (op.imm > 0 && idx < 2) {
					line.imm[idx++] = op.imm;
				}
			} else if (op.type == ARM64_OP_MEM) {
				line.mem_disp = op.mem.disp;
			}
		}

		v_code_line.push_back(std::move(line));
	}

	cs_free(insn, 1);
	cs_close(&handle);

	handle_candidate_offsets(v_code_line, candidate_offsets);
	return !candidate_offsets.empty();
}

} // namespace a64_find_imm_register_offset