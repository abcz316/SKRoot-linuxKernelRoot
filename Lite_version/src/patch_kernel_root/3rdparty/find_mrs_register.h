#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <time.h>
#include <capstone/capstone.h>


namespace a64_find_mrs_register {
constexpr int kMinRegisterOffset = 0x200;
struct code_line {
	uint64_t addr;
	arm64_insn cmd_id = ARM64_INS_INVALID;
	std::string op_str;
};

bool handle_mrs(const std::vector<code_line>& v_code_line, size_t& register_offset) {
	bool res = false;
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.cmd_id != ARM64_INS_MRS) {
			continue;
		}
		int xCurrentReg = 0;
		if (sscanf(item.op_str.c_str(), "x%d sp_el0", &xCurrentReg) != 1) {
			continue;
		}
		auto y = x + 1;
		if (y >= v_code_line.size()) {
			break;
		}

		size_t xFirstRegNum = 0;
		size_t xFirstRegOffset = 0;

		for (; y < v_code_line.size(); y++) {
			xFirstRegNum = 0;
			xFirstRegOffset = 0;
			auto& item2 = v_code_line[y];
			if (item2.cmd_id == ARM64_INS_LDR || item2.cmd_id == ARM64_INS_LDRSW) {
				std::stringstream fmt;
				fmt << "x%d, [x" << xCurrentReg << ", #%llx]";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			if (item2.cmd_id == ARM64_INS_ADD) {
				std::stringstream fmt;
				fmt << "x%d, x" << xCurrentReg << ", #%llx";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}

			if (xFirstRegOffset > kMinRegisterOffset) {
				break;
			}
		}
		if (xFirstRegOffset > kMinRegisterOffset) {
			register_offset = xFirstRegOffset;
			res = true;
			break;
		}
	}
	return res;
}

bool handle_and(const std::vector<code_line>& v_code_line, size_t& register_offset) {
	bool res = false;
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.cmd_id != ARM64_INS_AND) {
			continue;
		}
		int xCurrentReg = 0;
		int xLastSpReg = 0;
		if (sscanf(item.op_str.c_str(), "x%d, x%d, #0xffffffffffffc000", &xCurrentReg, &xLastSpReg) != 2) {
			continue;
		}
		auto y = x + 1;
		if (y >= v_code_line.size()) {
			break;
		}

		size_t xFirstRegNum = 0;
		size_t xFirstRegOffset = 0;

		for (; y < v_code_line.size(); y++) {
			xFirstRegNum = 0;
			xFirstRegOffset = 0;
			auto& item2 = v_code_line[y];
			if (item2.cmd_id == ARM64_INS_LDR || item2.cmd_id == ARM64_INS_LDRSW) {
				std::stringstream fmt;
				fmt << "x%d, [x" << xCurrentReg << ", #%llx]";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			if (item2.cmd_id == ARM64_INS_ADD) {
				std::stringstream fmt;
				fmt << "x%d, x" << xCurrentReg << ", #%llx";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}

			if (xFirstRegOffset > kMinRegisterOffset) {
				break;
			}
		}
		if (xFirstRegOffset > kMinRegisterOffset) {
			register_offset = xFirstRegOffset;
			res = true;
			break;
		}
	}
	return res;
}

bool handle_current_task_next_register_offset(const std::vector<code_line>& v_code_line, std::string& mode_name, size_t& register_offset) {
	bool _mrs = handle_mrs(v_code_line, register_offset);
	if (_mrs) {
		mode_name = "mrs";
		return _mrs;
	}
	bool _and = handle_and(v_code_line, register_offset);
	if (_and) {
		mode_name = "and";
		return true;
	}
	return false;
}

bool find_current_task_next_register_offset(const std::vector<char>& file_buf, size_t start, size_t end, std::string& mode_name, size_t& register_offset) {
	size_t code_size = end - start;
	bool res = false;
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
		line.op_str = insn->op_str;
		v_code_line.push_back(line);
		if (v_code_line.back().addr < code_size) continue;
		res = handle_current_task_next_register_offset(v_code_line, mode_name, register_offset);
		if (res) break;
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return res;
}
}