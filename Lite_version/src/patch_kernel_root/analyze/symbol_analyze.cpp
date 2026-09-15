#include "symbol_analyze.h"
#include "3rdparty/find_end_func_offset.h"

SymbolAnalyze::SymbolAnalyze(const std::vector<char> &file_buf) : m_file_buf(file_buf), m_sym_finder(file_buf) { }

SymbolAnalyze::~SymbolAnalyze() { }

bool SymbolAnalyze::analyze_kernel_symbol() {
	if (!m_sym_finder.init()) {
		std::cout << "Failed to initialize kallsyms lookup name" << std::endl;
		return false;
	}
	bool found = find_symbol_offset();
	printf_symbol_offset();
	if (!found) {
		std::cout << "Failed to find symbol offset" << std::endl;
		return false;
	}
	return true;
}

KernelSymbolOffset SymbolAnalyze::get_symbol_offset() {
	return m_sym_offset;
}

std::unordered_map<std::string, uint64_t> SymbolAnalyze::get_all_symbols() {
	return m_sym_finder.get_all_symbols();
}

bool SymbolAnalyze::find_symbol_offset() {
	auto find_addr = [this](SymbolCandidates names) {
		return m_sym_finder.find_addr(names);
	};
	auto find_region = [this](SymbolCandidates names) {
		return m_sym_finder.find_region(names);
	};
	m_sym_offset._text = find_addr({{"_text", false}});
	m_sym_offset._stext = find_addr({{"_stext", false}});
	m_sym_offset.die = find_region({{"die", false}});
	m_sym_offset.__drm_puts_coredump = find_region({ {"__drm_puts_coredump", false} });
	m_sym_offset.__drm_printfn_coredump = find_region({ {"__drm_printfn_coredump", false} });

	m_sym_offset.__do_execve_file = find_region({{"__do_execve_file", false}});
	m_sym_offset.do_execveat_common = find_region({
		{"do_execveat_common", false}, 
		{"do_execveat_common", true},
		});
	m_sym_offset.do_execve_common = find_region({
		{"do_execve_common", false},
		{"do_execve_common", true},
		});
	m_sym_offset.do_execveat = find_region({{"do_execveat", false}});
	m_sym_offset.do_execve = find_region({{"do_execve", false}});

	m_sym_offset.avc_denied = find_region({
		{"avc_denied", false},
		{"avc_denied", true},
		});

	m_sym_offset.audit_log_start = find_region({ {"audit_log_start", false} });

	m_sym_offset.filldir64 = find_region({
		{"filldir64", false},
		{"filldir64", true}
		});
	m_sym_offset.compat_filldir = find_region({
		{"compat_filldir", false},
		{"compat_filldir", true}
		});


	m_sym_offset.sys_getuid = find_region({
		{"sys_getuid", false},
		{"__arm64_sys_getuid", false},
		{"sys_getuid", true},
		});
	
	m_sym_offset.prctl_get_seccomp = find_region({{"prctl_get_seccomp", false}});  // backup: seccomp_filter_release
	
	m_sym_offset.__cfi_check = find_region({{"__cfi_check", false}});
	m_sym_offset.__cfi_check_fail = find_addr({{"__cfi_check_fail", false}});
	m_sym_offset.__cfi_slowpath_diag = find_addr({{"__cfi_slowpath_diag", false}});
	m_sym_offset.__cfi_slowpath = find_addr({{"__cfi_slowpath", false}});
	m_sym_offset.__ubsan_handle_cfi_check_fail_abort = find_addr({{"__ubsan_handle_cfi_check_fail_abort", false}});
	m_sym_offset.__ubsan_handle_cfi_check_fail = find_addr({{"__ubsan_handle_cfi_check_fail", false}});
	m_sym_offset.report_cfi_failure = find_addr({{"report_cfi_failure", false}});

	m_sym_offset.hkip_check_uid_root = find_addr({{"hkip_check_uid_root", false}});
	m_sym_offset.hkip_check_gid_root = find_addr({{"hkip_check_gid_root", false}});
	m_sym_offset.hkip_check_xid_root = find_addr({{"hkip_check_xid_root", false}});
	m_sym_offset.kti_randomize_init = find_region({{"kti_randomize_init", false}});

	return (m_sym_offset.do_execve || m_sym_offset.do_execveat || m_sym_offset.do_execveat_common) 
		&& m_sym_offset.avc_denied.valid()
		&& m_sym_offset.audit_log_start.valid()
		&& m_sym_offset.filldir64.valid()
		&& m_sym_offset.sys_getuid.valid()
		&& m_sym_offset.prctl_get_seccomp.valid();
}

void SymbolAnalyze::printf_symbol_offset() {
	std::cout << "_text:" << m_sym_offset._text << std::endl;
	std::cout << "_stext:" << m_sym_offset._stext << std::endl;
	if (m_sym_offset.die) std::cout << "die:" << m_sym_offset.die.offset << ", size:" << m_sym_offset.die.size << std::endl;
	if (m_sym_offset.__drm_puts_coredump) std::cout << "__drm_puts_coredump:" << m_sym_offset.__drm_puts_coredump.offset << ", size:" << m_sym_offset.__drm_printfn_coredump.size << std::endl;
	if (m_sym_offset.__drm_printfn_coredump) std::cout << "__drm_printfn_coredump:" << m_sym_offset.__drm_printfn_coredump.offset << ", size:" << m_sym_offset.__drm_printfn_coredump.size << std::endl;

	std::cout << "__do_execve_file:" << m_sym_offset.__do_execve_file.offset << ", size:" << m_sym_offset.__do_execve_file.size << std::endl;
	std::cout << "do_execveat_common:" << m_sym_offset.do_execveat_common.offset << ", size:" << m_sym_offset.do_execveat_common.size << std::endl;
	std::cout << "do_execve_common:" << m_sym_offset.do_execve_common.offset << ", size:" << m_sym_offset.do_execve_common.size << std::endl;
	std::cout << "do_execveat:" << m_sym_offset.do_execveat.offset << ", size:" << m_sym_offset.do_execveat.size << std::endl;
	std::cout << "do_execve:" << m_sym_offset.do_execve.offset << ", size:" << m_sym_offset.do_execve.size << std::endl;

	std::cout << "avc_denied:" << m_sym_offset.avc_denied.offset << ", size:" << m_sym_offset.avc_denied.size << std::endl;
	std::cout << "audit_log_start:" << m_sym_offset.audit_log_start.offset << ", size:" << m_sym_offset.audit_log_start.size << std::endl;
	std::cout << "filldir64:" << m_sym_offset.filldir64.offset << ", size:" << m_sym_offset.filldir64.size << std::endl;
	std::cout << "compat_filldir:" << m_sym_offset.compat_filldir.offset << ", size:" << m_sym_offset.compat_filldir.size << std::endl;

	std::cout << "sys_getuid:" << m_sym_offset.sys_getuid.offset << ", size:" << m_sym_offset.sys_getuid.size << std::endl;
	std::cout << "prctl_get_seccomp:" << m_sym_offset.prctl_get_seccomp.offset << ", size:" << m_sym_offset.prctl_get_seccomp.size << std::endl;

	// bypass cfi
	std::cout << "__cfi_check:" << m_sym_offset.__cfi_check.offset << ", size:" << m_sym_offset.__cfi_check.size << std::endl;
	std::cout << "__cfi_check_fail:" << m_sym_offset.__cfi_check_fail << std::endl;
	std::cout << "__cfi_slowpath_diag:" << m_sym_offset.__cfi_slowpath_diag << std::endl;
	std::cout << "__cfi_slowpath:" << m_sym_offset.__cfi_slowpath << std::endl;
	std::cout << "__ubsan_handle_cfi_check_fail_abort:" << m_sym_offset.__ubsan_handle_cfi_check_fail_abort << std::endl;
	std::cout << "__ubsan_handle_cfi_check_fail:" << m_sym_offset.__ubsan_handle_cfi_check_fail << std::endl;
	std::cout << "report_cfi_failure:" << m_sym_offset.report_cfi_failure << std::endl;

	// bypass huawei
	if (m_sym_offset.hkip_check_uid_root) std::cout << "hkip_check_uid_root:" << m_sym_offset.hkip_check_uid_root << std::endl;
	if (m_sym_offset.hkip_check_gid_root) std::cout << "hkip_check_gid_root:" << m_sym_offset.hkip_check_gid_root << std::endl;
	if (m_sym_offset.hkip_check_xid_root) std::cout << "hkip_check_xid_root:" << m_sym_offset.hkip_check_xid_root << std::endl;
	if (m_sym_offset.kti_randomize_init) std::cout << "kti_randomize_init:" << m_sym_offset.kti_randomize_init.offset << ", size:" << m_sym_offset.kti_randomize_init.size << std::endl;
}
