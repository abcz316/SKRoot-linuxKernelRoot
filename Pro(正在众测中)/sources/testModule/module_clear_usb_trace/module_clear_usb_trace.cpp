#include <iostream>
#include <unistd.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include "kernel_module_kit_umbrella.h"

void set_property_and_verify(const char* name, const char* value) {
    int rc = __system_property_set(name, value);
    if (rc != 0) {
        printf("set property failed: %s, err:%d\n", name, rc);
        return;
    }
    char buf[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name, buf);
    if (len < 0) {
        printf("get property failed: %s, err:%d\n", name, len);
        return;
    }

    if (std::strcmp(buf, value) != 0) {
        printf("set property invalid: %s\n", name);
        return;
    }
    printf("set property success: %s\n", name);
}

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    set_property_and_verify("sys.usb.adb.disabled", "");
    return 0;
}
SKROOT_MODULE_NAME("清理usb调试痕迹")
SKROOT_MODULE_VERSION("0.0.3")
SKROOT_MODULE_DESC("在系统早期阶段清除 USB/ADB 调试痕迹，关闭相关调试通道，提升设备隐匿性。")
SKROOT_MODULE_AUTHOR("SKRoot官方")
SKROOT_MODULE_UUID32("fb044e7a140697bb1a6d1ddb6f15b0b4")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_clear_usb_trace/update.json")