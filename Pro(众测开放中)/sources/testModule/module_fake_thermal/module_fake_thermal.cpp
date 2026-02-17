#include "patch_thermal_zone_get_temp.h"
#include "kernel_module_kit_umbrella.h"

// 开始修补内核
static KModErr patch_kernel_handler() {
    uint64_t thermal_zone_get_temp = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("thermal_zone_get_temp", thermal_zone_get_temp));
    printf("thermal_zone_get_temp, addr: %p\n", (void*)thermal_zone_get_temp);

    PatchBase patchBase;
    PatchThermalZoneGetTemp patchThermalZoneGetTemp(patchBase, thermal_zone_get_temp);
    KModErr err = patchThermalZoneGetTemp.patch_thermal_zone_get_temp();
    printf("patch thermal_zone_get_temp ret: %s\n", to_string(err).c_str());
    return err;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("Hello! module_fake_thermal!\n");
    KModErr err = patch_kernel_handler();
    printf("patch_kernel_handler ret:%s\n", to_string(err).c_str());
    return 0;
}

// SKRoot 模块名片
SKROOT_MODULE_NAME("温控解除")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("内核级伪装处理器温度曲线，实现去除温控，安全可靠。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_UUID32("kO8hT9tT2fB0hY9hV2bB4eJ6aY2nQ6kL")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_thermal/update.json")