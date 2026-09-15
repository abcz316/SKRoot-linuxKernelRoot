#pragma once
#include "kernel_version_parser.h"
#include "kallsyms_lookup_name.h"
#include "kallsyms_lookup_name_4_6_0.h"
#include "kallsyms_lookup_name_6_1_0.h"
#include "kallsyms_lookup_name_6_1_42.h"
#include "kallsyms_lookup_name_6_1_60.h"
#include "kallsyms_lookup_name_6_4_0.h"
#include "kallsyms_lookup_name_6_12_0.h"
#include <iostream>
#include <vector>
class KernelSymbolProxy
{
public:
	explicit KernelSymbolProxy(const std::vector<char>& file_buf);
	~KernelSymbolProxy();

public:
	bool init();
	uint64_t kallsyms_lookup_name(const char* name);
	uint64_t kallsyms_symbol_size(uint64_t cur_addr);
	std::unordered_map<std::string, uint64_t> kallsyms_lookup_names_like(const char* name);
	std::unordered_map<std::string, uint64_t> get_all_symbols();
	uint64_t get_kallsyms_relative_base();

private:
	bool try_init_lookup(IKallsymsLookup& lookup);
	uint64_t check_convert_b_insn(uint64_t symbol_offset);
	const std::vector<char>& m_file_buf;
	KernelVersionParser m_kernel_ver_parser;
	KallsymsLookupName m_kallsyms_lookup_name;
	KallsymsLookupName_4_6_0 m_kallsyms_lookup_name_4_6_0;
	KallsymsLookupName_6_1_0 m_kallsyms_lookup_name_6_1_0;
	KallsymsLookupName_6_1_42 m_kallsyms_lookup_name_6_1_42;
	KallsymsLookupName_6_1_60 m_kallsyms_lookup_name_6_1_60;
	KallsymsLookupName_6_4_0 m_kallsyms_lookup_name_6_4_0;
	KallsymsLookupName_6_12_0 m_kallsyms_lookup_name_6_12_0;
	IKallsymsLookup* m_active_lookup = nullptr;
};
