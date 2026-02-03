#pragma once
#include <iostream>
namespace skroot_env {
/***************************************************************************
 * 启用/禁用“开机失败保护”
 * 说明：检测到系统无法启动时，将自动禁用 SKRoot 环境框架，避免反复死机。
 * 参数: root_key     ROOT 权限密钥文本
 *       enabled      true 表示启用保护；false 表示禁用保护
 * 返回: OK 表示设置成功；其他值为错误码
 ***************************************************************************/
KModErr set_boot_fail_protect_enabled(const char* root_key, bool enabled);

/***************************************************************************
 * 查询“开机失败保护”是否已启用
 * 参数: root_key     ROOT 权限密钥文本
 * 返回: true 表示已启用保护；false 表示未启用
 ***************************************************************************/
bool is_boot_fail_protect_enabled(const char* root_key);

/***************************************************************************
 * 测试 SKRoot 核心基础能力
 *
 * 参数: root_key   ROOT 权限密钥文本
 *       item       要测试的项目
 *       out        测试输出文本（可为空字符串）
 *
 * 返回: OK 表示正常，其它错误码表示对应能力异常
 ***************************************************************************/
enum class BasicItem : uint32_t {
    Channel,            // 通道检查
    KernelBase,         // 内核起始地址检查
    WriteTest,          // 写入内存测试
    ReadTrampoline,     // 读取跳板测试
    WriteTrampoline,    // 写入跳板测试
};

KModErr test_skroot_basics(const char* root_key, BasicItem item, std::string& out);
/***************************************************************************
 * 测试 SKRoot 自带默认模块
 * 参数: root_key   ROOT权限密钥文本
 *       name       要测试的内部模块枚举
 *       out        输出的测试文本
 * 返回: OK 表示正常
***************************************************************************/
enum class DeafultModuleName: uint32_t {
    RootBridge,   // ROOT 提权模块
    SuRedirect,   // su 重定向模块
};
KModErr test_skroot_deafult_module(const char* root_key, DeafultModuleName name, std::string& out);

}
