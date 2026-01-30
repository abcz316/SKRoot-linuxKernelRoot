#pragma once
#include <vector>
#include <string>
#include <unistd.h>

namespace skroot_env {
namespace features {
namespace web_ui {
/***************************************************************************
* 启动模块WebUI服务器（异步）
* 参数: root_key            ROOT权限密钥文本
*       mod_uuid            模块UUID
*       out_port            输出端口
* 返回: OK 表示调用成功；其他值为错误码
***************************************************************************/
KModErr start_module_web_ui_server_async(const char* root_key, const char* mod_uuid, int &out_port);

} // namespace web_ui
} // namespace features
} // namespace skroot_env