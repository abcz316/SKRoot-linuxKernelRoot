#pragma once
#include "kernel_symbol_parser.h"
#include <sstream>

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

KernelSymbolParser::KernelSymbolParser(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_ver_parser(file_buf), m_kallsyms_lookup_name_4_6_0(file_buf), m_kallsyms_lookup_name(file_buf)
{
}

KernelSymbolParser::~KernelSymbolParser()
{
}

bool KernelSymbolParser::init_kallsyms_lookup_name() {

	std::string current_version = m_kernel_ver_parser.find_kernel_versions();
	if (current_version.empty()) {
		std::cout << "Failed to read Linux kernel version" << std::endl;
		return false;
	}
	std::cout << "Find the current Linux kernel version: " << current_version << std::endl;
	std::cout << std::endl;

	std::string threshold_version = "4.6.0";
	if (m_kernel_ver_parser.is_version_less_equal(current_version, threshold_version)) {
		// Old kernel system
		if (!m_kallsyms_lookup_name.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	}
	else {
		// New kernel system
		if (!m_kallsyms_lookup_name_4_6_0.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	}
	return true;
}

uint64_t KernelSymbolParser::kallsyms_lookup_name(const char* name, bool include_str_mode) {
	if (m_kallsyms_lookup_name_4_6_0.is_inited()) {
		return m_kallsyms_lookup_name_4_6_0.kallsyms_lookup_name(name, include_str_mode);
	} else if (m_kallsyms_lookup_name.is_inited()) {
		return m_kallsyms_lookup_name.kallsyms_lookup_name(name, include_str_mode);
	} else {
		return 0;
	}
}