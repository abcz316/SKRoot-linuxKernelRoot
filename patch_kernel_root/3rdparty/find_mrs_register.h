#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <time.h>
#include "capstone-4.0.2-win64/include/capstone/capstone.h"

struct code_line {
	uint64_t addr;
	std::string mnemonic;
	std::string op_str;
};


bool handle_mrs(const std::vector<code_line>& v_code_line, std::vector<size_t>& v_register_offset) {
	bool res = false;
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.mnemonic != "mrs") {
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
			if (item2.mnemonic.length() >= 3 && item2.mnemonic.substr(0, 3) == "ldr") {
				std::stringstream fmt;
				fmt << "x%d, [x" << xCurrentReg << ", #%llx]";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			if (item2.mnemonic.length() >= 3 && item2.mnemonic.substr(0, 3) == "add") {
				std::stringstream fmt;
				fmt << "x%d, x" << xCurrentReg << ", #%llx";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			
			if (xFirstRegOffset) {
				break;
			}
		}
		if (xFirstRegOffset == 0) {
			break;
		}
		if (xFirstRegOffset != 0x10) {
			v_register_offset.push_back(xFirstRegOffset);
			res = true;
			break;
		}
		size_t xSecondRegNum = 0;
		size_t xSecondRegOffset = 0;
		y = y + 1;
		if (y >= v_code_line.size()) {
			break;
		}
		for (; y < v_code_line.size(); y++) {
			xSecondRegNum = 0;
			xSecondRegOffset = 0;
			auto& item2 = v_code_line[y];
			if (item2.mnemonic.length() < 3 || item2.mnemonic.substr(0, 3) != "ldr") {
				continue;
			}
			std::stringstream fmt;
			fmt << "x%d, [x" << xFirstRegNum << ", #%llx]";
			if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xSecondRegNum, &xSecondRegOffset) != 2) {
				continue;
			}
			if (xSecondRegOffset) {
				break;
			}
		}
		if (xSecondRegOffset) {
			v_register_offset.push_back(xFirstRegOffset);
			v_register_offset.push_back(xSecondRegOffset);
			res = true;
			break;
		}
	}
	return res;
}

bool handle_and
(const std::vector<code_line>& v_code_line, std::vector<size_t>& v_register_offset) {
	bool res = false;
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.mnemonic != "and") {
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
			if (item2.mnemonic.length() >= 3 && item2.mnemonic.substr(0, 3) == "ldr") {
				std::stringstream fmt;
				fmt << "x%d, [x" << xCurrentReg << ", #%llx]";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			if (item2.mnemonic.length() >= 3 && item2.mnemonic.substr(0, 3) == "add") {
				std::stringstream fmt;
				fmt << "x%d, x" << xCurrentReg << ", #%llx";
				if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xFirstRegNum, &xFirstRegOffset) != 2) {
					continue;
				}
			}
			
			if (xFirstRegOffset) {
				break;
			}
		}
		if (xFirstRegOffset == 0) {
			break;
		}
		if (xFirstRegOffset != 0x10) {
			v_register_offset.push_back(xFirstRegOffset);
			res = true;
			break;
		}
		size_t xSecondRegNum = 0;
		size_t xSecondRegOffset = 0;
		y = y + 1;
		if (y >= v_code_line.size()) {
			break;
		}
		for (; y < v_code_line.size(); y++) {
			xSecondRegNum = 0;
			xSecondRegOffset = 0;
			auto& item2 = v_code_line[y];
			if (item2.mnemonic.length() < 3 || item2.mnemonic.substr(0, 3) != "ldr") {
				continue;
			}
			std::stringstream fmt;
			fmt << "x%d, [x" << xFirstRegNum << ", #%llx]";
			if (sscanf(item2.op_str.c_str(), fmt.str().c_str(), &xSecondRegNum, &xSecondRegOffset) != 2) {
				continue;
			}
			if (xSecondRegOffset) {
				break;
			}
		}
		if (xSecondRegOffset) {
			v_register_offset.push_back(xFirstRegOffset);
			v_register_offset.push_back(xSecondRegOffset);
			res = true;
			break;
		}
	}
	return res;
}

bool handle_current_task_next_register_offset(const std::string& group_name, const std::vector<code_line>& v_code_line, std::string& mode_name, std::vector<size_t>& v_register_offset) {
	bool _mrs = handle_mrs(v_code_line, v_register_offset);
	if (_mrs) {
		mode_name = "mrs";
		return _mrs;
	}
	bool _and = handle_and(v_code_line, v_register_offset);
	if (_and) {
		mode_name = "and";
		return true;
	}
	return false;
}

bool find_current_task_next_register_offset(const std::vector<char>& file_buf, size_t start, std::string & mode_name, std::vector<size_t> & v_register_offset) {
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
	size_t file_size = file_buf.size() - start;
	std::vector<code_line> v_code_line;
	while (cs_disasm_iter(handle, &code, &file_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.mnemonic = insn->mnemonic;
		line.op_str = insn->op_str;
		v_code_line.push_back(line);

		cs_detail* detail = insn->detail;
		if (detail->groups_count > 0 && v_code_line.size() >= 2) {
			std::string group_name = cs_group_name(handle, detail->groups[0]);
			res = handle_current_task_next_register_offset(group_name, v_code_line, mode_name, v_register_offset);
			if (res) {
				break;
			}
		}
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return res;
}
