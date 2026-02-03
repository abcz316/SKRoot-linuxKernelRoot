#include <iostream>
#include "kernel_module_kit_umbrella.h"

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_update] starting... \n");
    printf("[module_update] root_key len=%zu\n", strlen(root_key));
    printf("[module_update] module_private_dir=%s\n", module_private_dir);
    return 0;
}

// SKRoot 模块名片
SKROOT_MODULE_NAME("更新 URL 配置示例模块")
SKROOT_MODULE_VERSION("0.0.1")
SKROOT_MODULE_DESC("演示配置更新 JSON")
SKROOT_MODULE_AUTHOR("SKRoot官方教程")
SKROOT_MODULE_UUID32("62027df1409d6109da7e153d04915074")

/*
==========================
 更新 JSON 示例与说明书
==========================
SKRoot App 会定期检查该 JSON，并在发现新版本时向用户提示更新。

示例 JSON 内容如下：
{
    "version": "0.0.1",
    "zipUrl": "https://example.com/demo.zip",
    "changelog": "https://example.com/changelog.txt"
}

字段说明：
- version   : 最新模块版本号。
- zipUrl    : 模块更新包（ZIP 文件）下载地址。
- changelog : 更新说明文件，用于展示更新内容。
*/

// 在线更新 JSON 配置（演示用 example.com）
SKROOT_MODULE_UPDATE_JSON("https://example.com/update.json")

