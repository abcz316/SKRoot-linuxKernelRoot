#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchAvcDenied : public PatchBase
{
public:
	PatchAvcDenied(const PatchBase& patch_base, const SymbolRegion &avc_denied);
	~PatchAvcDenied();

	size_t patch_avc_denied(const SymbolRegion& hook_func_start_region, size_t current_avc_check_bl_func, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
private:
	SymbolRegion m_avc_denied = {0};
};