#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchFilldir64 : public PatchBase
{
public:
	PatchFilldir64(const PatchBase& patch_base, const SymbolRegion& filldir64);
	~PatchFilldir64();

	size_t patch_filldir64_root_key_guide(size_t root_key_mem_addr, const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
	size_t patch_filldir64_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	SymbolRegion m_filldir64 = { 0 };
	size_t m_filldir64_epilogue = 0;
};