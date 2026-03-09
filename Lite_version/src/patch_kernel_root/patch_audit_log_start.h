#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchAuditLogStart : public PatchBase
{
public:
	PatchAuditLogStart(const PatchBase& patch_base, size_t audit_log_start);
	~PatchAuditLogStart();

	size_t patch_audit_log_start(const SymbolRegion& hook_func_start_region, size_t current_avc_check_bl_func, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
private:
	size_t m_audit_log_start = {0};
	uint32_t m_audit_log_start_orig_entry_insn = 0;
};