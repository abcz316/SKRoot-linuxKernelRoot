#pragma once
#include "kernel_symbol_parser.h"
#include <iostream>
#include <vector>

struct KernelSymbolOffset {
	size_t _text = 0;
	size_t _stext = 0;
	size_t die = 0;

	size_t __do_execve_file = 0;
	size_t do_execveat_common = 0;
	size_t do_execve_common = 0;
	size_t do_execveat = 0;
	size_t do_execve = 0;

	size_t avc_denied = 0;
	size_t revert_creds = 0;
	size_t prctl_get_seccomp = 0;
	size_t __cfi_check = 0;
	size_t __cfi_check_fail = 0;
	size_t __cfi_slowpath_diag = 0;
	size_t __cfi_slowpath = 0;
	size_t __ubsan_handle_cfi_check_fail_abort = 0;
	size_t __ubsan_handle_cfi_check_fail = 0;
	size_t report_cfi_failure = 0;
};

class AnalyzeKernel
{
public:
	AnalyzeKernel(const std::vector<char> & file_buf);
	~AnalyzeKernel();

public:
	bool analyze_kernel_symbol();
	KernelSymbolOffset get_symbol_offset();
	bool is_kernel_version_less_equal(const std::string& ver);
private:
	bool find_symbol_offset();
	const std::vector<char>& m_file_buf;
	KernelSymbolParser m_kernel_sym_parser;
	KernelSymbolOffset m_kernel_sym_offset;
};