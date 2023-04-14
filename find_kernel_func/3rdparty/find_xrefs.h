#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <time.h>
#include "capstone-4.0.2-win64/include/capstone/capstone.h"

struct xrefs_info {
	size_t xrefs_location;
	size_t belong_function_entry;
};

struct code_line {
	uint64_t addr;
	std::string mnemonic;
	std::string op_str;
};

bool check_code_block_is_func_head(const std::vector<code_line>& v_code_block) {
	int stp_cnt = 0;
	bool exist_x29_x30_sp = false;
	for (size_t x = 0; x < v_code_block.size(); x++) {
		if (v_code_block[x].mnemonic == "stp") {
			if (v_code_block[x].op_str.find("x29, x30, [sp, #") != -1) {
				exist_x29_x30_sp = true;
			}
			stp_cnt++;
		}
	}
	return stp_cnt >= 3 ? true : false;
}

uint64_t get_code_block_func_entry_addr(const std::vector<code_line>& v_code_block) {
	if (v_code_block.size() == 0) {
		return 0;
	}
	for (size_t x = 0; x < v_code_block.size(); x++) {
		if (v_code_block[x].mnemonic == "hint" && v_code_block[x].op_str == "#0x19") {
			return v_code_block[x].addr;
		} else if (v_code_block[x].mnemonic == "sub" && v_code_block[x].op_str.find("sp, sp, #") != -1) {
			return v_code_block[x].addr;
		}
	}
	return v_code_block[0].addr;
}

void parse_code_block_adrp(uint64_t last_function_start_addr,
	const std::vector<code_line>& v_code_block,
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	for (size_t x = 0; x < v_code_block.size(); x++) {
		if (v_code_block[x].mnemonic != "adrp") {
			continue;
		}

		int xD = 0;
		size_t jump_addr = 0;
		if (sscanf(v_code_block[x].op_str.c_str(), "x%d, #0x%llx", &xD, &jump_addr) != 2) {
			continue;
		}
		size_t jump_op_offset = 0;
		for (size_t y = x + 1; y < v_code_block.size(); y++) {
			if (v_code_block[y].mnemonic == "add") { //TODO: if have sub?
				int x1, x2;
				if (sscanf(v_code_block[y].op_str.c_str(), "x%d, x%d, #0x%llx", &x1, &x2, &jump_op_offset) != 3) {
					continue;
				}
				if (x1 != x2 || x1 != xD) {
					jump_op_offset = 0;
				} else {
					break;
				}
			}
		}
		jump_addr += jump_op_offset;

		for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
			if (std::get<1>(iter->first) == 0 || std::get<1>(iter->first) != jump_addr) {
				continue;
			}
			if (iter->second) {
				iter->second->push_back({ v_code_block[x].addr, last_function_start_addr });
			}
		}
	}

}

void parse_code_block_with_xrefs(const std::string& group_name,
	const std::vector<code_line>& v_code_block,
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	static size_t last_function_start_addr = 0;
	if (v_code_block.size() == 0) {
		return;
	}
	if (check_code_block_is_func_head(v_code_block)) {
		last_function_start_addr = get_code_block_func_entry_addr(v_code_block);
	}
	parse_code_block_adrp(last_function_start_addr, v_code_block, result_map);
}

void parse_code_block_with_func_haed(const std::string& group_name,
	const std::vector<code_line>& v_code_block,
	std::map<size_t, std::shared_ptr<size_t>>& result_map) {
	static size_t last_function_start_addr = 0;
	if (v_code_block.size() == 0) {
		return;
	}
	if (check_code_block_is_func_head(v_code_block)) {
		last_function_start_addr = get_code_block_func_entry_addr(v_code_block);
	}

	for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
		bool match = false;
		for (size_t x = 0; x < v_code_block.size(); x++) {
			if (v_code_block[x].addr == iter->first) {
				match = true;
				break;
			}
		}
		if (!match) {
			continue;
		}
		if (iter->second) {
			*iter->second = last_function_start_addr;
		}
	}
}

void printf_xrefs_result_map(const std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	if (result_map.size() == 0) {
		printf("Search result is empty.\n");
		return;
	}
	for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
		if (!iter->second) {
			continue;
		}
		for (auto& xrefs_item : *iter->second) {
			printf("function %s xrefs location is->0x%llx,\nfunction %s entry range is->0x%llx\n\n", std::get<0>(iter->first).c_str(),
				xrefs_item.xrefs_location, std::get<0>(iter->first).c_str(), xrefs_item.belong_function_entry);
		}
	}
}

void printf_head_result_map(const std::map<size_t, std::shared_ptr<size_t>>& result_map) {
	if (result_map.size() == 0) {
		printf("Search result is empty.\n");
		return;
	}
	for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
		if (!iter->second) {
			continue;
		}
		printf("key location is->0x%llx, function entry range is->0x%llx\n", iter->first, *iter->second);
	}
}

void find_xrefs_link(const char* image, size_t image_size,
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	if (result_map.size() == 0) {
		return;
	}
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
	const uint8_t* code = (const uint8_t*)image;
	std::vector<code_line> v_code_block;
	uint64_t start_time = 0;
	while (cs_disasm_iter(handle, &code, &image_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.mnemonic = insn->mnemonic;
		line.op_str = insn->op_str;
		v_code_block.push_back(line);

		cs_detail* detail = insn->detail;
		if (detail->groups_count > 0 && v_code_block.size() > 2) {
			std::string group_name = cs_group_name(handle, detail->groups[0]);
			parse_code_block_with_xrefs(group_name, v_code_block, result_map);
			v_code_block.clear();
		}
		if ((time(NULL) - start_time) > 1) {
			start_time = time(NULL);
			float progress = (double)((double)insn->address * 100.0f / (double)image_size);
			progress = progress > 100.0f ? 100.0f : progress;
			printf("Current search location:0x%llx, percentage progress: %.2f%%\r", insn->address, progress);
		}
	}
	printf("\n");
	printf("\n");
	cs_free(insn, 1);
	cs_close(&handle);
}

void find_func_haed_link(const char* image, size_t image_size,
	std::map<size_t, std::shared_ptr<size_t>>& result_map) {
	if (result_map.size() == 0) {
		return;
	}
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
	const uint8_t* code = (const uint8_t*)image;
	std::vector<code_line> v_code_block;
	uint64_t start_time = 0;
	while (cs_disasm_iter(handle, &code, &image_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.mnemonic = insn->mnemonic;
		line.op_str = insn->op_str;
		v_code_block.push_back(line);

		cs_detail* detail = insn->detail;
		if (detail->groups_count > 0 && v_code_block.size() > 2) {
			std::string group_name = cs_group_name(handle, detail->groups[0]);
			parse_code_block_with_func_haed(group_name, v_code_block, result_map);
			v_code_block.clear();
		}
		if ((time(NULL) - start_time) > 1) {
			start_time = time(NULL);
			float progress = (double)((double)insn->address * 100.0f / (double)image_size);
			progress = progress > 100.0f ? 100.0f : progress;
			printf("Current search location:0x%llx, percentage progress: %.2f%%\r", insn->address, progress);
		}
	}
	printf("\n");
	printf("\n");
	cs_free(insn, 1);
	cs_close(&handle);
}
