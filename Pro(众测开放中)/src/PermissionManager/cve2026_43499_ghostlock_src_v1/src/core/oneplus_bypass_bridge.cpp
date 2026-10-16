#include "module_err_def.h"
#include "oneplus_bypass_bridge.h"
#include "oneplus_device_detect.h"

KModErr oneplus_bypass_stage1_and_2(const char *root_key, void (*cb)(const char *info));
extern "C" int check_oplus_device_bypass(void) {
    if (device_detect::is_oplus_device()) {
        KModErr err = oneplus_bypass_stage1_and_2("txEO2by4A0auZpUxL7Cji2aMR9olMylmoEyNLkoTaqYvuECE", nullptr);
        return static_cast<int>(to_num(err));
    }
    return 0;
}
