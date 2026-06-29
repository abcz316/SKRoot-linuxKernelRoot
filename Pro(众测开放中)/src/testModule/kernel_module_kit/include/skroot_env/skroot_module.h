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

enum class ModuleRunState : uint32_t {
    NotRunning = 0,         // 未运行
    Running,                // 运行中
    Abnormal,               // 运行异常
    RemovedPendingReboot,   // 已删除，待重启
};

struct module_record {
    module_desc desc;
    ModuleRunState state = ModuleRunState::NotRunning;
} __attribute__((packed));


/***************************************************************************
 * 获取已安装模块列表
 * 参数: root_key        ROOT权限密钥文本
 *       out_list        输出模块列表
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_all_modules_list(const char* root_key, std::vector<module_record>& out_list);

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
 * 开发者单次安装
 * 说明:
 *   将模块以“仅运行一次”模式安装，防止模块引发循环死机，避免无法开机。
 * 注意: 模块稳定后，请使用 install_module() 正常添加。
 ***************************************************************************/
KModErr install_module_dev_run_once(const char* root_key, const char* module_zip_path, std::string& out_reason);

/***************************************************************************
* 卸载模块
* 参数: root_key            ROOT权限密钥文本
*       mod_uuid            模块UUID
*       module_argv         需要传递的模块参数
* 返回: OK     表示调用成功；其他值为错误码
***************************************************************************/
KModErr uninstall_module(const char* root_key, const char* mod_uuid);
} // namespace skroot_env