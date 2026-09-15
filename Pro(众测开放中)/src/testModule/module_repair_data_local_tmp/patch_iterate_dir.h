#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchIterateDir : public PatchBase {
public:
	PatchIterateDir(const PatchBase& patch_base, uint64_t iterate_dir);
	~PatchIterateDir();

	KModErr patch_iterate_dir(uint64_t original_filldir64, uint64_t target_filldir64);
private:
	uint64_t m_iterate_dir = 0;
};