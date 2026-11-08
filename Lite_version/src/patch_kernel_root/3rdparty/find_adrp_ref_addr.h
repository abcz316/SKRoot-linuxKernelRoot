#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <time.h>
#include <cinttypes>
#include <capstone/capstone.h>

namespace a64_find_adrp_ref_addr {
struct code_line {
	uint64_t addr;
	arm64_insn cmd_id = ARM64_INS_INVALID;
	std::string op_str;
};
struct track_reg_info {
	int move_to_x_reg_num = -1;
	int64_t load_offset = -1;
};

static std::vector<track_reg_info> track_register_load_offset(const std::vector<code_line>& v_code_line, size_t start_index, int x_load_reg) {
	if (start_index >= v_code_line.size()) return {};
	std::vector<track_reg_info> result;
	for (size_t y = start_index; y < v_code_line.size(); y++) {
		track_reg_info t;
		std::stringstream fmt;
		auto& item = v_code_line[y];
		if (item.cmd_id == ARM64_INS_STR || item.cmd_id == ARM64_INS_LDR || item.cmd_id == ARM64_INS_LDRSW) {
			fmt << "x%d, [x" << x_load_reg << ", #%" SCNx64 "]";
			if (sscanf(item.op_str.c_str(), fmt.str().c_str(), &t.move_to_x_reg_num, &t.load_offset) != 2) continue;
		} else if (item.cmd_id == ARM64_INS_ADD) {
			fmt << "x%d, x" << x_load_reg << ", #%" SCNx64;
			if (sscanf(item.op_str.c_str(), fmt.str().c_str(), &t.move_to_x_reg_num, &t.load_offset) != 2) continue;
		} else continue;
		result.push_back(t);
	}
	return result;
}

static bool handle_adrp_target_addr(const std::vector<code_line>& v_code_line, size_t start, uint64_t& result) {
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.cmd_id != ARM64_INS_ADRP) continue;
		int x_reg = 0;
		uint64_t imm_u = 0;
		if (sscanf(item.op_str.c_str(), "x%d, #%" SCNx64, &x_reg, &imm_u) != 2) continue;

		int64_t imm = static_cast<int64_t>(imm_u);
		uint64_t insn_file_off = start + item.addr;
		uint64_t page_base = insn_file_off & ~0xFFFULL;
		uint64_t target_page = static_cast<uint64_t>(static_cast<int64_t>(page_base) + imm);

		std::vector<track_reg_info> track_info = track_register_load_offset(v_code_line, x + 1, x_reg);
		if (!track_info.size()) return false;
		result = target_page + track_info[0].load_offset;
		return true;
	}
	return false;
}

static bool find_adrp_ref_addr(const std::vector<char>& file_buf, size_t start, size_t end, uint64_t& addr) {
	size_t total_code_size = end - start;
	size_t remaining_size = total_code_size;
	bool res = false;
	csh handle;
	cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		abort();
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
	//cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);

	cs_insn* insn = cs_malloc(handle);
	uint64_t address = 0x0;
	const uint8_t* code = (const uint8_t*)&file_buf[0] + start;
	std::vector<code_line> v_code_line;
	v_code_line.reserve(total_code_size / 4);
	while (cs_disasm_iter(handle, &code, &remaining_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.cmd_id = static_cast<arm64_insn>(insn->id);
		line.op_str = insn->op_str;
		v_code_line.push_back(std::move(line));
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return handle_adrp_target_addr(v_code_line, start, addr);
}
}