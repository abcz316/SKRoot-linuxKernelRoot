#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <math.h>

static std::vector<char> read_file_buf(const std::string& file_path) {
	std::ifstream file(file_path, std::ios::binary | std::ios::ate);
	if (file) {
		auto size = file.tellg();
		std::vector<char> buffer(size);
		file.seekg(0, std::ios::beg);
		file.read(buffer.data(), size);
		file.close();
		return buffer;
	}
	return {};
}

static void get_rand_str(char* dest, int n) {
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++) {
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
}

static std::string generate_random_root_key() {
	const int key_len = 48;
	char root_key_data[key_len] = { 0 };
	get_rand_str(root_key_data, sizeof(root_key_data));
	std::string str_root_key(root_key_data, sizeof(root_key_data));
	return str_root_key;
}

static auto hex2byte(uint8_t* hex, uint8_t* str) -> void {
	char high, low;
	for (size_t i = 0, length = strlen((char*)hex); i < length; i += 2) {
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}

static bool write_file_bytes(const char* file_path, size_t offset, const char* bytes, size_t len) {
	std::fstream file_stream(file_path, std::ios::in | std::ios::out | std::ios::binary);
	if (!file_stream) {
		return false;
	}
	file_stream.seekp(offset);
	if (!file_stream.good()) {
		file_stream.close();
		return false;
	}
	file_stream.write(bytes, len);
	if (!file_stream.good()) {
		file_stream.close();
		return false;
	}
	file_stream.close();
	return true;
}

static size_t align8(size_t addr) {
	if (addr % 8 != 0) {
		addr = (addr + 7) & ~static_cast<size_t>(7);  // Align to next 8-byte boundary
	}
	return addr;
}
