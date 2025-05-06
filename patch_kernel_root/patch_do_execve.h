#pragma once
#include <iostream>
#include <vector>
#include "patch_kernel_root.h"
#include "analyze/analyze_kernel.h"
class PatchDoExecve
{
public:
	PatchDoExecve(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const AnalyzeKernel& analyze_kernel);
	~PatchDoExecve();

	size_t patch_do_execve(const std::string& str_root_key, size_t hook_func_start_addr,
		const std::vector<size_t>& task_struct_offset_cred,
		const std::vector<size_t>& task_struct_offset_seccomp,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	std::pair<size_t, size_t> get_do_execve_param();
	int get_atomic_usage_len();
	int get_securebits_padding();
	std::string get_cap_ability_max();
	int get_need_write_cap_cnt();
	const std::vector<char>& m_file_buf;
	const KernelSymbolOffset & m_sym;
	const AnalyzeKernel& m_analyze_kernel;
};