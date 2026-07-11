#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchSocInfoShow : public PatchBase {
public:
	PatchSocInfoShow(const PatchBase& patch_base, uint64_t soc_info_show);
	~PatchSocInfoShow();

	KModErr patch_soc_info_show(const std::string& fake_soc_sn);
private:
	uint64_t m_soc_info_show = 0;
};