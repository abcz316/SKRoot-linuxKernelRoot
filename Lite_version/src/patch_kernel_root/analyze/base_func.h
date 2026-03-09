#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>
#include <vector>
#include <math.h>
#include <cstring>

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

static std::string generate_random_str(std::size_t len) {
	static constexpr char alphabet[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789";
	static constexpr std::size_t alphabet_size = sizeof(alphabet) - 1;
	static std::mt19937_64 rng{
		static_cast<unsigned long>(std::chrono::steady_clock::now().time_since_epoch().count())
	};
	std::uniform_int_distribution<std::size_t> dist(0, alphabet_size - 1);
	std::string key;
	key.reserve(len);
	for (std::size_t i = 0; i < len; ++i) {
		key += alphabet[dist(rng)];
	}
	return key;
}


static auto hex2bytes(uint8_t* hex, uint8_t* str) -> void {
	char high, low;
	for (size_t i = 0, length = strlen((char*)hex); i < length; i += 2) {
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}

static std::string bytes2hex(const unsigned char* input, size_t length) {
	static const char HEX[16] = {
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'a', 'b',
	'c', 'd', 'e', 'f'
	};
	std::string str;
	str.reserve(length << 1);
	for (size_t i = 0; i < length; ++i) {
		int t = input[i];
		int a = t / 16;
		int b = t % 16;
		str.append(1, HEX[a]);
		str.append(1, HEX[b]);
	}
	return str;
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

template <size_t N>
static inline constexpr size_t align_up(size_t v) {
	static_assert((N & (N - 1)) == 0, "N must be power of two");
	return (v + (N - 1)) & ~(N - 1);
}

static inline uint32_t rd32_le(const std::vector<char>& buf, size_t off) {
	uint32_t v = 0;
	memcpy(&v, buf.data() + off, sizeof(v));
	return v;
}

static inline uint64_t rd64_le(const std::vector<char>& buf, size_t off) {
	uint64_t v = 0;
	memcpy(&v, buf.data() + off, sizeof(v));
	return v;
}