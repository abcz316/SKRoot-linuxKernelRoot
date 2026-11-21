#pragma once
#include <iostream>
#include <vector>
#include "kernel_module_kit_umbrella.h"

class PatchBase {
public:
	PatchBase(uint32_t cred_offset, uint32_t euid_offset);
	PatchBase(const PatchBase& other);
	~PatchBase();
protected:
	void emit_get_euid_to_w11(asmjit::a64::Assembler* a, asmjit::Label on_error = asmjit::Label());
	void emit_uid_to_appid(asmjit::a64::Assembler* a, asmjit::a64::GpW w_uid, asmjit::a64::GpW w_tmp1, asmjit::a64::GpW w_tmp2, asmjit::a64::GpW w_appid);
	void emit_match_current_appid_to_x10(asmjit::a64::Assembler* a, uint32_t target_uid);
	KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::a64::Assembler* a);
	KModErr patch_kernel_after_hook(uint64_t kaddr, const asmjit::a64::Assembler* a);

private:
	uint32_t m_cred_offset = 0;
	uint32_t m_euid_offset = 0;
};
