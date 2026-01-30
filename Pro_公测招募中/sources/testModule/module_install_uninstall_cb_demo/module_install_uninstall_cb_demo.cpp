#include <iostream>
#include "kernel_module_kit_umbrella.h"

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_cb_demo] hello!\n");
    return 0;
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    printf("[module_cb_demo] on install!!!\n");
    return "";
}

void module_on_uninstall(const char* root_key, const char* module_private_dir) {
    printf("[module_cb_demo] on uninstall!!!\n");
}

// SKRoot 模块名片
SKROOT_MODULE_NAME("安装/卸载回调示例模块")
SKROOT_MODULE_VERSION("0.0.1")
SKROOT_MODULE_DESC("演示模块安装、卸载回调")
SKROOT_MODULE_AUTHOR("SKRoot官方教程")
SKROOT_MODULE_UUID32("b7e4d333fd4689044b58b59e631a40e5")

SKROOT_MODULE_ON_INSTALL(module_on_install) // 配置安装模块回调
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall) // 配置卸载模块回调

