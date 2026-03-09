#pragma once
#include <iostream>
#include <vector>
#include <string.h>
#include "base_func.h"

#define A64_NOP 0xD503201F

static bool __is_really_empty(const std::vector<char>& file_buf, size_t start_pos) {
	const size_t must_empty_cnt = 12;
	for (size_t i = start_pos; i < start_pos + must_empty_cnt * 4; i += 4) {
		uint32_t w = rd32_le(file_buf, i);
		if (w == 0) return true;
		if (w != A64_NOP) return false;
	}
	return true;
}

static bool __is_really_work(const std::vector<char>& file_buf, size_t start_pos) {
	const size_t must_work_cnt = 80;
	for (size_t i = start_pos; i < start_pos + must_work_cnt * 4; i += 4) {
		uint32_t w = rd32_le(file_buf, i);
		if (w == 0) return false;
		if (w == A64_NOP) {
			if (__is_really_empty(file_buf, i)) {
				return false;
			}
		}
	}
	return true;
}

static size_t find_static_code_start(const std::vector<char>& file_buf) {
	if (file_buf.size() < 0x200) return 0;

	const size_t start_pos = 0x200;
	static_assert((start_pos & 0x3u) == 0, "start_pos 必须 4 字节对齐");

	size_t x = start_pos;
	for (; x < file_buf.size(); x += 4) {
		uint32_t w = rd32_le(file_buf, x);
		if (w == 0 || w == A64_NOP) continue;

		// check is work?
		if (__is_really_work(file_buf, x)) {
			return x;
		}
	}
	return 0;
}
