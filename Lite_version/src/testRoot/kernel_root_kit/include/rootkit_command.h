#pragma once
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "rootkit_err_def.h"
namespace kernel_root {
/***************************************************************************
 * 获取ROOT权限
 * 参数: str_root_key ROOT权限密钥文本
 * 返回: OK 表示成功
 ***************************************************************************/
KRootErr get_root(const char* str_root_key);

/***************************************************************************
 * 执行ROOT命令
 * 参数: str_root_key		ROOT权限密钥文本
			out_result		输出结果
 * 返回: OK 表示成功
 ***************************************************************************/
KRootErr run_root_cmd(const char* str_root_key, const char* cmd, std::string & out_result);
}
