#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"

#pragma pack(push, 1)
struct ExecveParam {
	uint32_t do_execve_addr = 0;
	uint8_t do_execve_filename_reg = 0;
	bool     is_single_char_ptr = false;
};
#pragma pack(pop)

class PatchDoExecve : public PatchBase
{
public:
	PatchDoExecve(const PatchBase& patch_base, const KernelSymbolOffset &sym);
	~PatchDoExecve();

	size_t patch_do_execve(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, size_t task_struct_seccomp_offset,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	void init_do_execve_param(const KernelSymbolOffset& sym);
	int get_need_write_cap_cnt();

	ExecveParam m_doexecve_reg_param = { 0 };
};