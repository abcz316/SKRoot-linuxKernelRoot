#pragma once
#include <unistd.h>
#include <iostream>

namespace skroot_env {
/***************************************************************************
 * 提升当前进程为 ROOT 权限
 * 参数: root_key  ROOT 权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_root(const char* root_key);
}
