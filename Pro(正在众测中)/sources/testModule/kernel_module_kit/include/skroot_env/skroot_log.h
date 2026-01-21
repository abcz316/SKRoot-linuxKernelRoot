#pragma once
#include <unistd.h>
#include <iostream>

namespace skroot_env {
/***************************************************************************
 * 读取 SKRoot 日志
 * 参数: root_key  ROOT权限密钥文本
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr read_skroot_log(const char* root_key, std::string& out);

/***************************************************************************
* 设置 SKRoot 日志开关
* 参数: root_key     ROOT权限密钥文本
*       enable       true 表示开启日志，false 表示关闭日志
* 返回: OK 表示设置成功；其他值为错误码
***************************************************************************/
KModErr set_skroot_log_enabled(const char* root_key, bool enable);

/***************************************************************************
* 查询 SKRoot 日志是否开启
* 参数: root_key     ROOT权限密钥文本
* 返回: true 表示开启日志，false表示关闭日志
***************************************************************************/
bool is_skroot_log_enabled(const char* root_key);
}
