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

void parse_code_block(uint64_t last_func_start,
	const std::vector<code_line> &v_code_block, 
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	for (size_t x = 0; x < v_code_block.size(); x++) {
		if (v_code_block[x].mnemonic == "adrp") {
			int xD = 0;
			size_t jump_addr = 0;
			if (sscanf(v_code_block[x].op_str.c_str(), "x%d, #0x%p", &xD, &jump_addr) == 2) {
				size_t jump_op_offset = 0;
				for (size_t y = x + 1; y < v_code_block.size(); y++) {
					if (v_code_block[y].mnemonic == "add") { //TODO: if have sub?
						int x1, x2;
						if (sscanf(v_code_block[y].op_str.c_str(), "x%d, x%d, #0x%p", &x1, &x2, &jump_op_offset) == 3) {
							if (x1 != x2 || x1 != xD) {
								jump_op_offset = 0;
							} else {
								break;
							}
						}
					}
				}
				jump_addr += jump_op_offset;

				for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
					if (std::get<1>(iter->first) == jump_addr) {
						if (iter->second) {
							iter->second->push_back({ v_code_block[x].addr, last_func_start });
						}
					}

				}
			}
		}
	}
}

void printf_xrefs_result_map(const std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>>& result_map) {
	for (auto iter = result_map.begin(); iter != result_map.end(); iter++) {
		if (!iter->second) {
			continue;
		}
		for (auto & xrefs_item : *iter->second) {
			printf("%s: xrefs location->%p, belong to function entry->%p\n", std::get<0>(iter->first).c_str(),
				xrefs_item.xrefs_location, xrefs_item.belong_function_entry);
		}
	}
}

void find_xrefs_link(const char* image, size_t image_size,
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>> & result_map) {

	csh handle;
	cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		abort();
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	//cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);

	cs_insn *insn = cs_malloc(handle);
	uint64_t address = 0x0;
	const uint8_t* code = (const uint8_t*)image;
	std::vector<code_line> v_code_block;
	size_t last_func_start = 0;
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
			if (group_name == "return") {
				last_func_start = insn->address + 4;
			}
			parse_code_block(last_func_start, v_code_block, result_map);
			v_code_block.clear();
		}
		if ((time(NULL) - start_time) > 5) {
			start_time = time(NULL);
			float progress = (float)((float)insn->address * 100 / (float)image_size);
			progress = progress > 100.0f ? 100.0f : progress;
			printf("progress: %.2f%%\n", progress);
		}
	}
	cs_free(insn, 1);
	cs_close(&handle);
}
