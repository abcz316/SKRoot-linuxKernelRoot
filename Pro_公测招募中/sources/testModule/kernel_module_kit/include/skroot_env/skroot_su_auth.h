#pragma once
#include <unistd.h>
#include <iostream>
namespace skroot_env {
struct su_auth_item {
    char app_package_name[256] = {0};
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

}