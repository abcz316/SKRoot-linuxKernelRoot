#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchCompatFilldir : public PatchBase {
public:
	PatchCompatFilldir(const PatchBase& patch_base, uint64_t compat_filldir);
	~PatchCompatFilldir();

	KModErr patch_compat_filldir(const std::set<std::string>& names, const std::set<uint64_t>& ino_set);
private:
	uint64_t m_compat_filldir = 0;
};