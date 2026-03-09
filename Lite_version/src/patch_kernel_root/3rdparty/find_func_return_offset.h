#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <sstream>
#include <regex>
#include <string>
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <capstone/capstone.h>

namespace a64_find_func_return_offset {

	constexpr size_t k_npos = static_cast<size_t>(-1);
	constexpr int k_max_jump_region = 1024 * 1024 * 5; // 5MB

	enum class ret_mode : uint8_t {
		none = 0,
		ret,
		retaa,
		retab
	};

	struct code_line {
		uint64_t addr = 0;
		arm64_insn cmd_id = ARM64_INS_INVALID;
		arm64_cc cc_id = ARM64_CC_INVALID;
		int64_t final_imm = 0;
	};

	static inline ret_mode get_ret_mode(arm64_insn id) {
		switch (id) {
		case ARM64_INS_RET:   return ret_mode::ret;
		case ARM64_INS_RETAA: return ret_mode::retaa;
		case ARM64_INS_RETAB: return ret_mode::retab;
		default: return ret_mode::none;
		}
	}

	static inline const char* get_ret_mode_name(ret_mode mode) {
		switch (mode) {
		case ret_mode::ret: return "RET";
		case ret_mode::retaa: return "RETAA";
		case ret_mode::retab: return "RETAB";
		default: return "";
		}
	}

	static inline bool is_ret_insn(arm64_insn id) {
		return get_ret_mode(id) != ret_mode::none;
	}

	static inline bool is_offset_jump_asm(const code_line& line) {
		return line.cmd_id == ARM64_INS_B;
	}

	static inline bool is_force_jump_asm(const code_line& line) {
		if (line.cmd_id == ARM64_INS_BR) return true;
		return line.cmd_id == ARM64_INS_B &&
			(line.cc_id == ARM64_CC_INVALID ||
				line.cc_id == ARM64_CC_AL ||
				line.cc_id == ARM64_CC_NV);
	}

	static size_t index_by_addr(const std::vector<code_line>& v, uint64_t addr) {
		auto it = std::lower_bound(v.begin(), v.end(), addr, [](const code_line& L, uint64_t a) { return L.addr < a; });
		if (it != v.end() && it->addr == addr) return static_cast<size_t>(it - v.begin());
		return k_npos;
	}

	static void scan_from_index(const std::vector<code_line>& v_code_line,
		size_t start_idx,
		std::set<uint64_t>& branch_history,
		std::vector<uint64_t>& out_ret_addrs,
		std::vector<uint64_t>& out_branch_anchors) {
		for (size_t x = start_idx; x < v_code_line.size(); ++x) {
			const auto& line = v_code_line[x];

			if (is_offset_jump_asm(line)) {
				const int64_t addr = line.final_imm;
				if (addr > 0 && addr < static_cast<int64_t>(line.addr + k_max_jump_region)) {
					const uint64_t fork = static_cast<uint64_t>(addr);
					if (!branch_history.count(fork)) {
						branch_history.insert(fork);
						out_branch_anchors.push_back(fork);
					}
				}

				if (is_force_jump_asm(line)) break;
				continue;
			}

			if (is_ret_insn(line.cmd_id)) out_ret_addrs.push_back(line.addr);
		}
	}

	static bool handle_candidate_offsets(const std::vector<code_line>& v_code_line,
		size_t& candidate_offsets) {
		std::vector<uint64_t> ret_addrs;
		std::vector<uint64_t> branch_anchors;
		std::set<uint64_t> branch_history;

		// scan main line
		scan_from_index(v_code_line, 0, branch_history, ret_addrs, branch_anchors);

		// scan branch lines
		while (!branch_anchors.empty()) {
			const uint64_t fork_addr = branch_anchors.back();
			branch_anchors.pop_back();

			const size_t idx = index_by_addr(v_code_line, fork_addr);
			if (idx == k_npos) {
				return false; // need more code line
			}
			scan_from_index(v_code_line, idx, branch_history, ret_addrs, branch_anchors);
		}

		if (!ret_addrs.empty()) {
			candidate_offsets = static_cast<size_t>(
				*std::max_element(ret_addrs.begin(), ret_addrs.end())
				);
			return true;
		}

		return false;
	}

	static bool find_func_return_offset(const std::vector<char>& file_buf,
		size_t start,
		size_t& candidate_offsets) {
		bool res = false;

		csh handle;
		cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

		cs_insn* insn = cs_malloc(handle);
		if (!insn) {
			printf("Failed to allocate Capstone instruction object.\n");
			cs_close(&handle);
			abort();
		}

		uint64_t address = 0;
		const uint8_t* code = reinterpret_cast<const uint8_t*>(file_buf.data()) + start;
		size_t file_size = file_buf.size() - start;

		std::vector<code_line> v_code_line;
		v_code_line.reserve(100);

		size_t last_ret_cnt = 0;
		size_t ret_cnt = 0;
		ret_mode found_ret_mode = ret_mode::none;

		while (cs_disasm_iter(handle, &code, &file_size, &address, insn)) {
			code_line line;
			line.addr = insn->address;
			line.cmd_id = static_cast<arm64_insn>(insn->id);
			line.cc_id = insn->detail->arm64.cc;

			for (int y = 0; y < insn->detail->arm64.op_count; ++y) {
				if (insn->detail->arm64.operands[y].type == ARM64_OP_IMM) {
					int64_t imm = insn->detail->arm64.operands[y].imm;
					if (imm > 0) {
						line.final_imm = imm;
					}
				}
			}

			const ret_mode cur_ret_mode = get_ret_mode(line.cmd_id);
			if (cur_ret_mode != ret_mode::none) {
				++ret_cnt;

				if (found_ret_mode == ret_mode::none) {
					found_ret_mode = cur_ret_mode;
				} else if (found_ret_mode != cur_ret_mode) {
					printf("Error: mixed return instructions are not allowed. First found %s, but later found %s at address 0x%llx.\n",
						get_ret_mode_name(found_ret_mode),
						get_ret_mode_name(cur_ret_mode),
						static_cast<unsigned long long>(line.addr));
					abort();
				}
			}

			v_code_line.push_back(line);
			if (v_code_line.size() > 0x10000) break;

			if (ret_cnt == last_ret_cnt) continue;
			last_ret_cnt = ret_cnt;

			res = handle_candidate_offsets(v_code_line, candidate_offsets);
			if (res) break;
		}

		cs_free(insn, 1);
		cs_close(&handle);
		return res;
	}

} // namespace a64_find_func_return_offset