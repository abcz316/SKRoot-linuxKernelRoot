#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <string_view>

#ifndef SIMPLE_HASH_STR_MAX
#define SIMPLE_HASH_STR_MAX 16   // 包含末尾 '\0'
#endif

#if SIMPLE_HASH_STR_MAX < 7
#error SIMPLE_HASH_STR_MAX must be at least 7
#endif

class SimpleHashUtil {
private:
	static constexpr char kAlphabet[] =
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.";

	static constexpr std::size_t kAlphabetSize = sizeof(kAlphabet) - 1;

	static inline uint64_t mix64(uint64_t x) {
		x ^= x >> 30;
		x *= 0xbf58476d1ce4e5b9ULL;
		x ^= x >> 27;
		x *= 0x94d049bb133111ebULL;
		x ^= x >> 31;
		return x;
	}

	static inline void hash16(std::string_view s, uint64_t& h1, uint64_t& h2) {
		h1 = 0x123456789abcdef0ULL;
		h2 = 0xfedcba9876543210ULL;

		for (unsigned char c : s) {
			h1 ^= c;
			h1 = mix64(h1);

			h2 += static_cast<uint64_t>(c) + 0x9e3779b97f4a7c15ULL;
			h2 = mix64(h2);
		}

		h1 ^= static_cast<uint64_t>(s.size()) * 0x9e3779b97f4a7c15ULL;
		h2 ^= static_cast<uint64_t>(s.size()) * 0xc2b2ae3d27d4eb4fULL;

		h1 = mix64(h1);
		h2 = mix64(h2);
	}

	static inline uint64_t next_state(uint64_t& x) {
		x ^= x >> 12;
		x ^= x << 25;
		x ^= x >> 27;
		return x * 2685821657736338717ULL;
	}

public:
	using HashString = std::array<char, SIMPLE_HASH_STR_MAX>;

	static inline HashString to_random_string(std::string_view input) {
		HashString out{};
		out.fill('\0');

		uint64_t h1 = 0;
		uint64_t h2 = 0;
		hash16(input, h1, h2);

		uint64_t seed = mix64(h1 ^ (h2 + 0x9e3779b97f4a7c15ULL));

		constexpr std::size_t kMinVisibleLen = 6;
		constexpr std::size_t kMaxVisibleLen = SIMPLE_HASH_STR_MAX - 1;

		uint64_t len_state = mix64(seed ^ 0xD6E8FEB86659FD93ULL);
		const uint64_t limit = UINT64_MAX - (UINT64_MAX % kMaxVisibleLen);
		while (len_state >= limit) {
			len_state = mix64(len_state + 0x9E3779B97F4A7C15ULL);
		}

		std::size_t len = static_cast<std::size_t>(len_state % kMaxVisibleLen) + 1;

		if (len < kMinVisibleLen) {
			len = kMinVisibleLen;
		}

		uint64_t state = seed ^ h1 ^ (h2 << 1);

		for (std::size_t i = 0; i < len; ++i) {
			uint64_t r = next_state(state);
			out[i] = kAlphabet[r % kAlphabetSize];
		}

		out[len] = '\0';
		return out;
	}
};