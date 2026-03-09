#pragma once
#include <iostream>

#include "rootkit_err_def.h"

namespace kernel_root {

/***************************************************************************
 * 安装 su（超级用户）环境
 * 参数:
 *   str_root_key	ROOT 权限密钥文本
 *   err            输出: 错误码
 * 返回: 成功返回 su 可执行文件的绝对路径；失败返回空字符串，并通过 err 返回错误码。
 ***************************************************************************/
KRootErr install_su(const char* str_root_key, std::string & out_su_full_path);


/***************************************************************************
 * 卸载 su 环境
 * 参数:
 *   str_root_key   ROOT 权限密钥文本
 * 返回: KRootErr::OK 表示卸载成功 其余为错误码
 ***************************************************************************/
KRootErr uninstall_su(const char* str_root_key);

} // namespace kernel_root
