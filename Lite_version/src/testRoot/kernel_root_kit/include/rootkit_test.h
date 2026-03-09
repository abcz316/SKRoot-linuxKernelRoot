#pragma once
#include <iostream>
#include <unistd.h>
namespace kernel_root {

/***************************************************************************
 * 获取 ROOT 测试报告
 * 作用: 测试 ROOT 权限，收集并返回当前进程的 UID/GID、
 *       能力集（capabilities）、seccomp、securebits 及 SELinux 状态等信息
 * 参数: str_root_key   ROOT 权限密钥文本
 * 返回: 状态描述字符串
 ***************************************************************************/
const char* get_root_test_report(const char* str_root_key);

}