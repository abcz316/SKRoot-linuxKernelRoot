#pragma once
#include <string.h>
#include <unistd.h>
/***************************************************************************
 * 安装模块回调（可选）：SKROOT_MODULE_ON_INSTALL(callback)
 * 调用时机：仅模块解包完成、即将开始安装前触发；可拒绝安装。
 *
 * 参数：
 *   root_key            ROOT 密钥文本。
 *   module_private_dir  模块私有目录（受隐藏保护；需隐藏的文件请放在此目录）。
 *
 * 返回值：
 *   返回 ""            ：允许安装继续
 *   返回 非空字符串     ：拒绝安装（输出该信息并终止安装流程）
 ***************************************************************************/
std::string module_on_install(const char* root_key, const char* module_private_dir);

/***************************************************************************
 * 卸载模块回调（可选）：SKROOT_MODULE_ON_UNINSTALL(callback)
 * 调用时机：仅模块即将被删除前触发；用于清理与收尾。
 *
 * 参数：
 *   root_key            ROOT 密钥文本。
 *   module_private_dir  模块私有目录（受隐藏保护；需隐藏的文件请放在此目录）。
 ***************************************************************************/
void module_on_uninstall(const char* root_key, const char* module_private_dir);
