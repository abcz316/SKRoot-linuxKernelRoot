#pragma once
#include "____DO_NOT_EDIT____/private_desc_parser.h"
#include "module_web_ui_http_handler.h"
#include "module_base_install_callback.h"

/***************************************************************************
 * SKRoot 模块入口函数（必须提供）
 * 被执行时机：在 zygote64 进程启动前。
 * 参数：
 *   root_key           ROOT 密钥文本。
 *   module_private_dir	模块私有目录（受隐藏保护；需隐藏的文件请放在此目录）。
 * 返回值：默认 0；任意返回值仅记录到日志，便于排查。
 * 说明：skroot_module_main 返回后，代表本模块执行结束。如需继续运行请fork();
 ***************************************************************************/
int skroot_module_main(const char* root_key, const char* module_private_dir);

/***************************************************************************
 * 必填元数据（不填写将导致模块无法加载）
 ***************************************************************************/
// SKRoot 模块名称（必填）
#define SKROOT_MODULE_NAME(name)            ___MOD_NAME(name)

// SKRoot 模块版本号（必填）
#define SKROOT_MODULE_VERSION(ver)          ___MOD_VERSION(ver)

// SKRoot 模块描述（必填）
#define SKROOT_MODULE_DESC(desc)            ___MOD_DESC(desc)

// SKRoot 模块作者（必填）
#define SKROOT_MODULE_AUTHOR(author)        ___MOD_AUTHOR(author)

// SKRoot 模块 UUID32（必填，32 个随机字符 [0-9a-zA-Z]）
#define SKROOT_MODULE_UUID32(str32)         ___MOD_UUID32(str32)

/***************************************************************************
 * 可选能力（按需填写）
 ***************************************************************************/
// WebUI（可选）：Web管理页面
#define SKROOT_MODULE_WEB_UI(WebUIHandlerClass)     ___MOD_WEB_UI(WebUIHandlerClass)

// 安装模块回调（可选）：可拒绝安装。参考：module_install_callback.h
#define SKROOT_MODULE_ON_INSTALL(callback)      ___MOD_ON_INSTALL(callback)

// 卸载模块回调（可选）：用于清理与收尾。参考：module_install_callback.h
#define SKROOT_MODULE_ON_UNINSTALL(callback)    ___MOD_ON_UNINSTALL(callback)

// 更新 JSON（可选）：如"https://example.com/xxx.json"
#define SKROOT_MODULE_UPDATE_JSON(url)          ___MOD_UPDATE_JSON(url)
