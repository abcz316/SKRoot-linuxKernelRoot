#pragma once
#include <vector>
#include <string>
#include <unistd.h>
#include "skroot_installer.h"

namespace skroot_env {
struct module_desc {
    char name[1024] = {0};              // SKRoot 模块名称
    char version[1024] = {0};           // SKRoot 模块版本
    char desc[4096] = {0};              // SKRoot 模块描述信息
    char author[1024] = {0};            // SKRoot 模块作者
    char uuid[1024] = {0};              // SKRoot 模块UUID
    char update_json[1024] = {0};       // SKRoot 更新信息
    bool web_ui = false;
    SkrootSdkVersion min_sdk_ver = {0};
} __attribute__((packed));

enum class ModuleListMode : uint8_t {
    All = 0,      // 默认：全部已安装模块
    RunningOnly,  // 仅当前正在运行的模块
};
/***************************************************************************
 * 获取已安装的所有模块列表
 * 参数: root_key        ROOT权限密钥文本
 *       out_list       输出模块列表信息
 *       mode           列表模式：全部/仅运行中
 * 返回: OK 表示成功；其它值为错误码
 * 
 ***************************************************************************/
KModErr get_all_modules_list(const char* root_key, std::vector<module_desc>& out_list, ModuleListMode mode);

/***************************************************************************
* 解析指定模块的描述信息
* 参数: root_key            ROOT权限密钥文本
*       module_zip_path     模块 ZIP 文件路径
*       out_desc            输出描述信息
* 返回: OK 表示解析成功；其他值为错误码
***************************************************************************/
KModErr parse_module_desc_from_zip_file(const char* root_key, const char* module_zip_path, module_desc& out_desc);

/***************************************************************************
* 安装模块
* 参数: root_key            ROOT权限密钥文本
*       module_zip_path     模块 ZIP 文件路径
*       out_reason          [输出] 若模块拒绝安装，则返回拒绝原因文本；
* 返回: OK     表示调用成功；其他值为错误码
***************************************************************************/
KModErr install_module(const char* root_key, const char* module_zip_path, std::string& out_reason);

/***************************************************************************
* 卸载模块
* 参数: root_key            ROOT权限密钥文本
*       mod_uuid            模块UUID
*       module_argv         需要传递的模块参数
* 返回: OK     表示调用成功；其他值为错误码
***************************************************************************/
KModErr uninstall_module(const char* root_key, const char* mod_uuid);
} // namespace skroot_env