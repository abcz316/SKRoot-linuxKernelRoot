#pragma once
#include "kernel_symbol_parser.h"
#include <iostream>
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

struct KernelSymbolOffset {
	size_t _text = 0;
	size_t _stext = 0;
	SymbolRegion die = { 0 };
	SymbolRegion arm64_notify_die = { 0 };
	SymbolRegion __drm_printfn_coredump = { 0 };

	size_t __do_execve_file = 0;
	size_t do_execveat_common = 0;
	size_t do_execve_common = 0;
	size_t do_execveat = 0;
	size_t do_execve = 0;

	SymbolRegion avc_denied = { 0 };
	size_t audit_log_start = { 0 };
	size_t filldir64 = 0;

	SymbolRegion sys_getuid = { 0 };
	SymbolRegion prctl_get_seccomp = { 0 };

	SymbolRegion __cfi_check = { 0 };
	size_t __cfi_check_fail = 0;
	size_t __cfi_slowpath_diag = 0;
	size_t __cfi_slowpath = 0;
	size_t __ubsan_handle_cfi_check_fail_abort = 0;
	size_t __ubsan_handle_cfi_check_fail = 0;
	size_t report_cfi_failure = 0;

	//huawei
	size_t hkip_check_uid_root = 0;
	size_t hkip_check_gid_root = 0;
	size_t hkip_check_xid_root = 0;
};

class SymbolAnalyze
{
public:
	SymbolAnalyze(const std::vector<char> & file_buf);
	~SymbolAnalyze();

public:
	bool analyze_kernel_symbol();
	KernelSymbolOffset get_symbol_offset();
private:
	bool find_symbol_offset();
	void printf_symbol_offset();
	uint64_t kallsyms_matching_single(const char* name, bool fuzzy = false);
	std::unordered_map<std::string, uint64_t> kallsyms_matching_all(const char* name);
	SymbolRegion parse_symbol_region(uint64_t offset);
	std::unordered_map<std::string, SymbolRegion> parse_symbols_region(const std::unordered_map<std::string, uint64_t>& symbols);

	const std::vector<char>& m_file_buf;
	KernelSymbolParser m_sym_parser;
	KernelSymbolOffset m_sym_offset;
};