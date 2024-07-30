#pragma once
#include "analyze_kernel.h"

AnalyzeKernel::AnalyzeKernel(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_sym_parser(file_buf)
{
}

AnalyzeKernel::~AnalyzeKernel()
{
}

bool AnalyzeKernel::analyze_kernel_symbol() {
	if (!m_kernel_sym_parser.init_kallsyms_lookup_name()) {
		std::cout << "Failed to initialize kallsyms lookup name" << std::endl;
		return false;
	}
	if (!find_symbol_offset()) {
		std::cout << "Failed to find symbol offset" << std::endl;
		return false;
	}
	return true;
}

KernelSymbolOffset AnalyzeKernel::get_symbol_offset() {
	return m_kernel_sym_offset;
}

bool AnalyzeKernel::find_symbol_offset() {
	m_kernel_sym_offset._text_offset = m_kernel_sym_parser.kallsyms_lookup_name("_text");
	m_kernel_sym_offset._stext_offset = m_kernel_sym_parser.kallsyms_lookup_name("_stext");
	m_kernel_sym_offset.panic_offset = m_kernel_sym_parser.kallsyms_lookup_name("panic");
	m_kernel_sym_offset.do_execve_offset = m_kernel_sym_parser.kallsyms_lookup_name("do_execve");
	m_kernel_sym_offset.do_execveat_offset = m_kernel_sym_parser.kallsyms_lookup_name("do_execveat");
	m_kernel_sym_offset.do_execveat_common_offset = m_kernel_sym_parser.kallsyms_lookup_name("do_execveat_common");
	if (m_kernel_sym_offset.do_execveat_common_offset == 0) {
		m_kernel_sym_offset.do_execveat_common_offset = m_kernel_sym_parser.kallsyms_lookup_name("do_execveat_common", true);
	}
	m_kernel_sym_offset.avc_denied_offset = m_kernel_sym_parser.kallsyms_lookup_name("avc_denied");
	if (m_kernel_sym_offset.avc_denied_offset == 0) {
		m_kernel_sym_offset.avc_denied_offset = m_kernel_sym_parser.kallsyms_lookup_name("avc_denied", true);
	}

	m_kernel_sym_offset.revert_creds_offset = m_kernel_sym_parser.kallsyms_lookup_name("revert_creds");
	m_kernel_sym_offset.prctl_get_seccomp_offset = m_kernel_sym_parser.kallsyms_lookup_name("prctl_get_seccomp"); // backup: seccomp_filter_release
	m_kernel_sym_offset.__cfi_check_offset = m_kernel_sym_parser.kallsyms_lookup_name("__cfi_check");
	m_kernel_sym_offset.__cfi_check_fail_offset = m_kernel_sym_parser.kallsyms_lookup_name("__cfi_check_fail");
	m_kernel_sym_offset.__cfi_slowpath_diag_offset = m_kernel_sym_parser.kallsyms_lookup_name("__cfi_slowpath_diag");
	m_kernel_sym_offset.__cfi_slowpath_offset = m_kernel_sym_parser.kallsyms_lookup_name("__cfi_slowpath");
	m_kernel_sym_offset.__ubsan_handle_cfi_check_fail_abort_offset = m_kernel_sym_parser.kallsyms_lookup_name("__ubsan_handle_cfi_check_fail_abort");
	m_kernel_sym_offset.__ubsan_handle_cfi_check_fail_offset = m_kernel_sym_parser.kallsyms_lookup_name("__ubsan_handle_cfi_check_fail");
	m_kernel_sym_offset.report_cfi_failure_offset = m_kernel_sym_parser.kallsyms_lookup_name("report_cfi_failure");
	return (m_kernel_sym_offset.do_execve_offset || m_kernel_sym_offset.do_execveat_offset || m_kernel_sym_offset.do_execveat_common_offset
		) && m_kernel_sym_offset.avc_denied_offset && m_kernel_sym_offset.revert_creds_offset && m_kernel_sym_offset.prctl_get_seccomp_offset;
}