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
	uint64_t addr;
	arm64_insn cmd_id = ARM64_INS_INVALID;
	int64_t mem_disp = 0;
	int64_t imm[2] = {0};
};

bool is_offset_jump_asm(const code_line& line) {
	return line.cmd_id == ARM64_INS_B;
}

void handle_candidate_offsets(const std::vector<code_line>& v_code_line, std::vector<int64_t> &candidate_offsets) {
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& line = v_code_line[x];
		if (is_offset_jump_asm(line)) continue;
		if(line.mem_disp > 0) candidate_offsets.push_back(line.mem_disp);
		if(line.imm[0] > 0) candidate_offsets.push_back(line.imm[0]);
		if(line.imm[1] > 0) candidate_offsets.push_back(line.imm[1]);
	}
}

bool find_imm_register_offset(const std::vector<char>& file_buf, size_t start, size_t end, std::vector<int64_t>& candidate_offsets) {
	size_t code_size = end - start;
	csh handle;
	cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		abort();
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	//cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);

	cs_insn* insn = cs_malloc(handle);
	uint64_t address = 0x0;
	const uint8_t* code = (const uint8_t*)&file_buf[0] + start;
	std::vector<code_line> v_code_line;
	v_code_line.reserve(code_size / 4);
	while (cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.cmd_id = (arm64_insn)insn->id;
		int idx = 0;
		for (auto y = 0; y < insn->detail->arm64.op_count; y++) {
			if (insn->detail->arm64.operands[y].type == ARM64_OP_IMM) {
				auto imm = insn->detail->arm64.operands[y].imm;
				if (imm > 0) line.imm[idx++] = imm;
			}
			if (insn->detail->arm64.operands[y].type == ARM64_OP_MEM) {
				line.mem_disp = insn->detail->arm64.operands[y].mem.disp;
			}
		}
		v_code_line.push_back(line);
		if (v_code_line.back().addr < code_size) continue;
		handle_candidate_offsets(v_code_line, candidate_offsets);
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return !!candidate_offsets.size();
}
}