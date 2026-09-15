#pragma once

#include "kernel_symbol_proxy.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

struct SymbolRegion {
	uint64_t offset = 0;
	uint64_t size = 0;

	void consume(uint64_t n) {
		offset += n;
		size -= n;
	}

	[[nodiscard]] constexpr bool valid() const noexcept { return offset != 0; }
	explicit constexpr operator bool() const noexcept { return valid(); }
};

using SymbolCandidate = std::pair<const char*, bool>;
using SymbolCandidates = std::initializer_list<SymbolCandidate>;

class KernelSymbolFinder {
public:
	explicit KernelSymbolFinder(const std::vector<char>& file_buf);

	bool init();
	std::unordered_map<std::string, uint64_t> get_all_symbols();

	uint64_t find_one(const char* name, bool fuzzy = false);
	std::unordered_map<std::string, uint64_t> find_all(const char* name);
	uint64_t find_addr(SymbolCandidates names);
	SymbolRegion find_region(SymbolCandidates names);

	SymbolRegion parse_region(uint64_t offset);
	std::unordered_map<std::string, SymbolRegion> parse_regions(const std::unordered_map<std::string, uint64_t>& symbols);

	uint64_t get_kallsyms_relative_base();
private:
	const std::vector<char>& m_file_buf;
	KernelSymbolProxy m_symbol_proxy;
};
