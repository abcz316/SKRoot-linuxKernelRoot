#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchMtkHbtFilldir64 : public PatchBase {
public:
	PatchMtkHbtFilldir64(const PatchBase& patch_base, uint64_t hbt_filldir64);
	~PatchMtkHbtFilldir64();

	KModErr generate_hook_fake_filldir64(const std::set<std::string>& names, const std::set<uint64_t>& ino_set, uint64_t & out_func_kaddr);

	private:
	KModErr create_kcfi_kernel_function(uint64_t reference_func, const std::vector<uint8_t>& shellcode, uint64_t& out_func_kaddr);

	uint64_t m_hbt_filldir64 = 0;
};