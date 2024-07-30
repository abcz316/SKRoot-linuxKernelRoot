#pragma once
#include "kernel_symbol_parser.h"
#include <iostream>
#include <vector>

struct KernelSymbolOffset {
	size_t _text_offset = 0;
	size_t _stext_offset = 0;
	size_t panic_offset = 0;
	size_t do_execve_offset = 0;
	size_t do_execveat_offset = 0;
	size_t do_execveat_common_offset = 0;
	size_t avc_denied_offset = 0;
	size_t revert_creds_offset = 0;
	size_t prctl_get_seccomp_offset = 0;
	size_t __cfi_check_offset = 0;
	size_t __cfi_check_fail_offset = 0;
	size_t __cfi_slowpath_diag_offset = 0;
	size_t __cfi_slowpath_offset = 0;
	size_t __ubsan_handle_cfi_check_fail_abort_offset = 0;
	size_t __ubsan_handle_cfi_check_fail_offset = 0;
	size_t report_cfi_failure_offset = 0;
};

class AnalyzeKernel
{
public:
	AnalyzeKernel(const std::vector<char> & file_buf);
	~AnalyzeKernel();

public:
	bool analyze_kernel_symbol();
	KernelSymbolOffset get_symbol_offset();
private:
	bool find_symbol_offset();
	const std::vector<char>& m_file_buf;
	KernelSymbolParser m_kernel_sym_parser;
	KernelSymbolOffset m_kernel_sym_offset;
};