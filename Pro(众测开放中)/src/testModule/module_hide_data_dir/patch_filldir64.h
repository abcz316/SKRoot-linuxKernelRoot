#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchFilldir64 : public PatchBase {
public:
	PatchFilldir64(const PatchBase& patch_base, uint64_t filldir64);
	~PatchFilldir64();

	KModErr patch_filldir64(const std::set<std::string>& hide_dir_name);
private:
	uint64_t m_filldir64 = 0;
};