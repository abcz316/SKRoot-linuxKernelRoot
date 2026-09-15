#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchCompatFilldir : public PatchBase
{
public:
	PatchCompatFilldir(const PatchBase& patch_base, const SymbolRegion& compat_filldir);
	~PatchCompatFilldir();

	size_t patch_compat_filldir_root_key_guide(size_t root_key_mem_addr, const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
	size_t patch_compat_filldir_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	SymbolRegion m_compat_filldir = { 0 };
	size_t m_compat_filldir_epilogue = 0;
};