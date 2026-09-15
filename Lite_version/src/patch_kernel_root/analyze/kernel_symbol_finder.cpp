#include "kernel_symbol_finder.h"

#include "3rdparty/find_end_func_offset.h"

#include <algorithm>

KernelSymbolFinder::KernelSymbolFinder(const std::vector<char>& file_buf)
	: m_file_buf(file_buf), m_symbol_proxy(file_buf) {
}

bool KernelSymbolFinder::init() {
	return m_symbol_proxy.init();
}

std::unordered_map<std::string, uint64_t> KernelSymbolFinder::get_all_symbols() {
	return m_symbol_proxy.get_all_symbols();
}

uint64_t KernelSymbolFinder::find_one(const char* name, bool fuzzy) {
	if (!fuzzy) return m_symbol_proxy.kallsyms_lookup_name(name);

	auto symbols = find_all(name);
	return symbols.empty() ? 0 : symbols.begin()->second;
}

std::unordered_map<std::string, uint64_t> KernelSymbolFinder::find_all(const char* name) {
	return m_symbol_proxy.kallsyms_lookup_names_like(name);
}

uint64_t KernelSymbolFinder::find_addr(SymbolCandidates names) {
	for (const auto& [name, fuzzy] : names) {
		uint64_t addr = find_one(name, fuzzy);
		if (addr) return addr;
	}
	return 0;
}

SymbolRegion KernelSymbolFinder::find_region(SymbolCandidates names) {
	for (const auto& [name, fuzzy] : names) {
		uint64_t addr = find_one(name, fuzzy);
		if (!addr) continue;

		auto region = parse_region(addr);
		if (region.valid()) return region;
	}
	return {};
}

SymbolRegion KernelSymbolFinder::parse_region(uint64_t offset) {
	using namespace a64_find_end_func_offset;

	SymbolRegion result;
	result.offset = offset;
	if (!result.valid()) return result;

	size_t candidate_offset = 0;
	if (!find_end_func_offset(m_file_buf, offset, candidate_offset)) return result;

	uint64_t candidate_size = candidate_offset + 4;
	uint64_t kallsyms_size = m_symbol_proxy.kallsyms_symbol_size(offset);
	result.size = kallsyms_size ? std::min(candidate_size, kallsyms_size) : candidate_size;
	return result;
}

std::unordered_map<std::string, SymbolRegion> KernelSymbolFinder::parse_regions(
	const std::unordered_map<std::string, uint64_t>& symbols) {
	std::unordered_map<std::string, SymbolRegion> results;
	for (const auto& [func_name, offset] : symbols) {
		if (func_name.find(".cfi_jt") != std::string::npos) continue;
		results.emplace(func_name, parse_region(offset));
	}
	return results;
}

uint64_t KernelSymbolFinder::get_kallsyms_relative_base() {
	return m_symbol_proxy.get_kallsyms_relative_base();
}
