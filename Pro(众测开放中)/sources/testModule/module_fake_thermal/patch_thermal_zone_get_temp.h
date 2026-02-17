#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"

class PatchThermalZoneGetTemp : public PatchBase {
public:
	PatchThermalZoneGetTemp(const PatchBase& patch_base, uint64_t thermal_zone_get_temp);
	~PatchThermalZoneGetTemp();

	KModErr patch_thermal_zone_get_temp();
private:
	uint64_t m_thermal_zone_get_temp = 0;
};