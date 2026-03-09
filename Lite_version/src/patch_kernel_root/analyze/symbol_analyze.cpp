#include "symbol_analyze.h"
#include "3rdparty/find_func_return_offset.h"

SymbolAnalyze::SymbolAnalyze(const std::vector<char> &file_buf) : m_file_buf(file_buf), m_sym_parser(file_buf) { }

SymbolAnalyze::~SymbolAnalyze() { }

bool SymbolAnalyze::analyze_kernel_symbol() {
	if (!m_sym_parser.init_kallsyms_lookup_name()) {
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

bool SymbolAnalyze::find_symbol_offset() {
	auto find_addr = [this](std::initializer_list<std::pair<const char *, bool>> names) -> uint64_t {
		for (auto &n : names) {
			uint64_t addr = kallsyms_matching_single(n.first, n.second);
			if (addr)
				return addr;
		}
		return 0;
	};

	auto find_region = [this](std::initializer_list<std::pair<const char *, bool>> names) -> SymbolRegion {
		for (auto &n : names) {
			uint64_t addr = kallsyms_matching_single(n.first, n.second);
			if (!addr)
				continue;
			auto region = parse_symbol_region(addr);
			if (region.valid())
				return region;
		}
		return {};
	};
	m_sym_offset._text = find_addr({{"_text", false}});
	m_sym_offset._stext = find_addr({{"_stext", false}});
	m_sym_offset.die = find_region({{"die", false}});
	m_sym_offset.arm64_notify_die = find_region({{"arm64_notify_die", false}});
	m_sym_offset.__drm_printfn_coredump = find_region({{"__drm_printfn_coredump", false}});

	m_sym_offset.__do_execve_file = find_addr({{"__do_execve_file", false}});
	m_sym_offset.do_execveat_common = find_addr({
		{"do_execveat_common", false}, 
		{"do_execveat_common", true},
		});
	m_sym_offset.do_execve_common = find_addr({
		{"do_execve_common", false},
		{"do_execve_common", true},
		});
	m_sym_offset.do_execveat = find_addr({{"do_execveat", false}});
	m_sym_offset.do_execve = find_addr({{"do_execve", false}});

	m_sym_offset.avc_denied = find_region({
		{"avc_denied", false},
		{"avc_denied", true},
		});

	m_sym_offset.audit_log_start = find_addr({ {"audit_log_start", false} });

	m_sym_offset.filldir64 = find_addr({
		{"filldir64", false},
		{"filldir64", true}
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

	return (m_sym_offset.do_execve || m_sym_offset.do_execveat || m_sym_offset.do_execveat_common) 
		&& m_sym_offset.avc_denied.valid()
		&& m_sym_offset.audit_log_start
		&& m_sym_offset.filldir64
		&& m_sym_offset.sys_getuid.valid()
		&& m_sym_offset.prctl_get_seccomp.valid();
}

void SymbolAnalyze::printf_symbol_offset() {
	std::cout << "_text:" << m_sym_offset._text << std::endl;
	std::cout << "_stext:" << m_sym_offset._stext << std::endl;
	if (m_sym_offset.die) std::cout << "die:" << m_sym_offset.die.offset << ", size:" << m_sym_offset.die.size << std::endl;
	if (m_sym_offset.arm64_notify_die) std::cout << "arm64_notify_die:" << m_sym_offset.arm64_notify_die.offset << ", size:" << m_sym_offset.arm64_notify_die.size << std::endl;
	if (m_sym_offset.__drm_printfn_coredump) std::cout << "__drm_printfn_coredump:" << m_sym_offset.__drm_printfn_coredump.offset << ", size:" << m_sym_offset.__drm_printfn_coredump.size << std::endl;

	std::cout << "__do_execve_file:" << m_sym_offset.__do_execve_file << std::endl;
	std::cout << "do_execveat_common:" << m_sym_offset.do_execveat_common << std::endl;
	std::cout << "do_execve_common:" << m_sym_offset.do_execve_common << std::endl;
	std::cout << "do_execveat:" << m_sym_offset.do_execveat << std::endl;
	std::cout << "do_execve:" << m_sym_offset.do_execve << std::endl;

	std::cout << "avc_denied:" << m_sym_offset.avc_denied.offset << ", size:" << m_sym_offset.avc_denied.size << std::endl;
	std::cout << "audit_log_start:" << m_sym_offset.audit_log_start << std::endl;
	std::cout << "filldir64:" << m_sym_offset.filldir64 << std::endl;

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
}

uint64_t SymbolAnalyze::kallsyms_matching_single(const char* name, bool fuzzy) {
	if (fuzzy) {
		auto map = kallsyms_matching_all(name);
		if (map.size()) {
			return map.begin()->second;
		}
		return 0;
	}
	return m_sym_parser.kallsyms_lookup_name(name);
}

std::unordered_map<std::string, uint64_t> SymbolAnalyze::kallsyms_matching_all(const char* name) {
	return m_sym_parser.kallsyms_lookup_names_like(name);
}

SymbolRegion SymbolAnalyze::parse_symbol_region(uint64_t offset) {
	using namespace a64_find_func_return_offset;
	SymbolRegion results;
	results.offset = offset;
	if (!results.valid()) return results;
	size_t candidate_offsets = 0;
	if (!find_func_return_offset(m_file_buf, offset, candidate_offsets)) return results;
	results.size = candidate_offsets + 4;
	return results;
}

std::unordered_map<std::string, SymbolRegion> SymbolAnalyze::parse_symbols_region(const std::unordered_map<std::string, uint64_t>& symbols) {
	std::unordered_map<std::string, SymbolRegion> results;
	for (const auto& [func_name, offset] : symbols) {
		if (func_name.find(".cfi_jt") != std::string::npos) { continue; }
		results.emplace(func_name, parse_symbol_region(offset));
	}
	return results;
}