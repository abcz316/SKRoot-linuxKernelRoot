#include "kernel_symbol_proxy.h"
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include "3rdparty/aarch64_asm_helper.h"
#include "aarch64_simulate_insn.h"
#include "aarch64_insn.h"

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

KernelSymbolProxy::KernelSymbolProxy(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_ver_parser(file_buf)
	, m_kallsyms_lookup_name_6_12_0(file_buf)
	, m_kallsyms_lookup_name_6_4_0(file_buf)
	, m_kallsyms_lookup_name_6_1_60(file_buf)
	, m_kallsyms_lookup_name_6_1_42(file_buf)
	, m_kallsyms_lookup_name_6_1_0(file_buf)
	, m_kallsyms_lookup_name_4_6_0(file_buf)
	, m_kallsyms_lookup_name(file_buf)
{
}

KernelSymbolProxy::~KernelSymbolProxy()
{
}

bool KernelSymbolProxy::init() {
	std::string current_version = m_kernel_ver_parser.get_kernel_version();
	std::string current_tag = m_kernel_ver_parser.get_kernel_tag();
	if (current_version.empty()) {
		std::cout << "Failed to read Linux kernel version" << std::endl;
		return false;
	}
	std::cout << "linux kernel version: " << current_version << std::endl;
	std::cout << "linux kernel tag: " << current_tag << std::endl;
	std::cout << std::endl;

	if (m_kernel_ver_parser.is_kernel_version_less("4.4.0")) { // android special
		if (!try_init_lookup(m_kallsyms_lookup_name)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("4.6.0")) {
		if (!try_init_lookup(m_kallsyms_lookup_name)) {
			if (!try_init_lookup(m_kallsyms_lookup_name_4_6_0)) {
				std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
				return false;
			}
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.1.0")) {
		if (!try_init_lookup(m_kallsyms_lookup_name_4_6_0)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.1.42")) {
		if (!try_init_lookup(m_kallsyms_lookup_name_6_1_0)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.1.60")) {
		if (!try_init_lookup(m_kallsyms_lookup_name_6_1_42)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.4.0")) {
		if (!try_init_lookup(m_kallsyms_lookup_name_6_1_60)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if(m_kernel_ver_parser.is_kernel_version_less("6.12.0")) {
		if (!try_init_lookup(m_kallsyms_lookup_name_6_4_0)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else {
		if (!try_init_lookup(m_kallsyms_lookup_name_6_12_0)) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	}
	return true;
}

uint64_t KernelSymbolProxy::kallsyms_lookup_name(const char* name) {
	if (!m_active_lookup || !m_active_lookup->is_inited()) return 0;
	uint64_t symbol = m_active_lookup->kallsyms_lookup_name(name);
	symbol = check_convert_b_insn(symbol);
	return symbol;
}

uint64_t KernelSymbolProxy::kallsyms_symbol_size(uint64_t cur_addr) {
	if (!m_active_lookup || !m_active_lookup->is_inited()) return 0;
	return m_active_lookup->kallsyms_symbol_size(cur_addr);
}

std::unordered_map<std::string, uint64_t> KernelSymbolProxy::kallsyms_lookup_names_like(const char* name) {
	if (!m_active_lookup || !m_active_lookup->is_inited()) return {};
    static const std::vector<std::string> skip_suffixes = {
        ".cfi_jt",
    };
	std::unordered_map<std::string, uint64_t> all_symbols = m_active_lookup->kallsyms_on_each_symbol();
    std::unordered_map<std::string, uint64_t> result;
    for (const auto& [sym_name, addr] : all_symbols) {
        if (sym_name.find(name) == std::string::npos) {
            continue;
		}
        bool skip = std::any_of(
            skip_suffixes.begin(), skip_suffixes.end(),
            [&](const std::string& suf) {
                return sym_name.size() >= suf.size() && sym_name.compare(sym_name.size() - suf.size(), suf.size(), suf) == 0;
            });
        if (skip) {
            continue;
		}
		uint64_t new_addr = check_convert_b_insn(addr);
        result[sym_name] = new_addr;
    }
    return result;
}

std::unordered_map<std::string, uint64_t> KernelSymbolProxy::get_all_symbols() {
	if (!m_active_lookup || !m_active_lookup->is_inited()) return {};
	return m_active_lookup->kallsyms_on_each_symbol();
}

uint64_t KernelSymbolProxy::get_kallsyms_relative_base() {
	if (!m_active_lookup || !m_active_lookup->is_inited()) return 0;
	return m_active_lookup->get_kallsyms_relative_base();
}

bool KernelSymbolProxy::try_init_lookup(IKallsymsLookup& lookup) {
	if (!lookup.init()) return false;
	m_active_lookup = &lookup;
	return true;
}

uint64_t KernelSymbolProxy::check_convert_b_insn(uint64_t symbol_offset) {
	if (symbol_offset > m_file_buf.size() - sizeof(uint32_t)) {
		return symbol_offset;
	}
	uint32_t cmd = *(uint32_t*)&m_file_buf[symbol_offset];
	if (!symbol_offset || !aarch64_insn_is_b(cmd)) {
		return symbol_offset;
	}
	int32_t jump_offset = bbl_displacement(cmd);
	return symbol_offset + jump_offset;
}
