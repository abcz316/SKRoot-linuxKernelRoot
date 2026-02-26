#pragma once
#include <iostream>
#include <filesystem>
#include "analyze/base_func.h"

#define ROOT_KEY_LEN 48
#define FOLDER_HEAD_ROOT_KEY_LEN 16

#define IF_EXIT(cond) do { if (cond) { printf("[ERROR] Patch empty addr!\n"); system("pause"); exit(0); } } while (0)

#define PATCH_AND_CONSUME(region, call_expr) \
    do { \
        size_t __sz = (call_expr); \
        IF_EXIT(!__sz); \
        IF_EXIT(!region.offset); \
        (region).consume(__sz); \
    } while (0)

struct patch_bytes_data {
	std::string str_bytes;
	size_t write_addr = 0;
};

static size_t patch_ret_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	if (start == 0) return 0;
	vec_out_patch_bytes_data.push_back({ "C0035FD6", start });
	return 4;
}

static size_t patch_ret_1_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	if (start == 0) return 0;
	vec_out_patch_bytes_data.push_back({ "200080D2C0035FD6", start });
	return 8;
}

static size_t patch_ret_0_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	if (start == 0) return 0;
	vec_out_patch_bytes_data.push_back({ "E0031F2AC0035FD6", start });
	return 8;
}

static size_t patch_data(const std::vector<char>& file_buf, size_t start, void* buf, size_t buf_size, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	if (start == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)buf, buf_size);
	vec_out_patch_bytes_data.push_back({ str_bytes, start });
	return buf_size;
}