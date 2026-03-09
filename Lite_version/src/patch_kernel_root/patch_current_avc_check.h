#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchCurrentAvcCheck : public PatchBase
{
public:
	PatchCurrentAvcCheck(const PatchBase& patch_base);
	~PatchCurrentAvcCheck();

	size_t patch_current_avc_check_bl_func(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
};