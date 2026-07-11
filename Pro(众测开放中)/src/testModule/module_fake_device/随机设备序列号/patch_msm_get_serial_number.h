#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchMsmGetSerialNumber : public PatchBase {
public:
	PatchMsmGetSerialNumber(const PatchBase& patch_base, uint64_t msm_get_serial_number);
	~PatchMsmGetSerialNumber();

	KModErr patch_msm_get_serial_number(const std::string& fake_soc_sn);
private:
	uint64_t m_msm_get_serial_number = 0;
};