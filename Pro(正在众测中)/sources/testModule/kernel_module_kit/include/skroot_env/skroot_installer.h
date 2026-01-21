#pragma once
#include <vector>
#include <string>
#include <unistd.h>

namespace skroot_env {
/***************************************************************************
 * 安装 SKRoot 环境
 * 说明: 首次使用前必须调用此函数，用于创建 SKRoot 所需的环境文件。
 * 参数: root_key   ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr install_skroot_environment(const char* root_key);

/***************************************************************************
 * 卸载 SKRoot 环境
 * 说明: 彻底删除所有SKRoot环境文件。
 * 参数: root_key  ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr uninstall_skroot_environment(const char* root_key);

/***************************************************************************
 * 获取当前 SKRoot 环境状态
 * 参数: root_key  ROOT权限密钥文本
 * 返回: 环境状态信息
 ***************************************************************************/
enum class SkrootEnvState : uint32_t {
    NotInstalled = 0, // 未安装
    Running      = 1, // 运行中
    Fault        = 2  // 故障
};
SkrootEnvState get_skroot_environment_state(const char* root_key);

/***************************************************************************
 * 查询已安装的 SKRoot 环境版本号
 * 参数: root_key  ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
struct SkrootSdkVersion { uint32_t major = 0, minor = 0, patch = 0; };
KModErr get_installed_skroot_environment_version(const char* root_key, SkrootSdkVersion& out_ver);

/***************************************************************************
 * 读取当前 SDK 的版本号
 * 返回：SDK版本号
 ***************************************************************************/
SkrootSdkVersion get_sdk_version();
}

constexpr bool operator<(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return std::tie(a.major, a.minor, a.patch) < std::tie(b.major, b.minor, b.patch);
}

constexpr bool operator==(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return std::tie(a.major, a.minor, a.patch) == std::tie(b.major, b.minor, b.patch);
}

constexpr bool operator!=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return !(a == b);
}

constexpr bool operator>(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return b < a;
}

constexpr bool operator<=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return !(b < a);
}

constexpr bool operator>=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return !(a < b);
}