#pragma once
#include <unistd.h>
#include <iostream>
namespace skroot_env {
// SU 授权项
struct su_auth_item {
    char app_package_name[256] = {0}; // APP 包名
};

// SU 嗅探记录项
struct su_probe_item {
    char app_package_name[256] = {0}; // APP 包名；无法唯一确定时为 appId 字符串
    uint32_t app_id = 0;              // appId（uid % 100000）
    int probe_count = 0;              // 嗅探次数
    uint64_t last_probe_time_s = 0;   // 最后嗅探时间（Unix 秒）
};

/***************************************************************************
 * 获取 SU 授权列表
 * 参数: root_key   ROOT权限密钥文本
 *       out_pkgs   输出：APP包名列表
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_su_auth_list(const char* root_key, std::vector<su_auth_item>& out_pkgs);

/***************************************************************************
 * 添加APP到 SU 授权列表
 * 参数: root_key           ROOT权限密钥文本
 *       app_package_name   APP包名
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr add_su_auth_list(const char* root_key, const char* app_package_name);

/***************************************************************************
 * 从 SU 授权列表中移除指定 APP
 * 参数: root_key           ROOT权限密钥文本
 *       app_package_name   APP包名
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr remove_su_auth_list(const char* root_key, const char* app_package_name);

/***************************************************************************
 * 清空 SU 授权列表
 * 参数: root_key   ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr clear_su_auth_list(const char* root_key);

/***************************************************************************
 * 获取 SU 嗅探记录
 * 参数: root_key      ROOT权限密钥文本
 *       out_records   输出：统计当次开机期间，试图嗅探系统底层 su 文件的 APP 列表信息
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_su_probe_records(const char* root_key, std::vector<su_probe_item>& out_records);

/***************************************************************************
 * 清空 SU 嗅探记录
 * 参数: root_key      ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr clear_su_probe_records(const char* root_key);

}