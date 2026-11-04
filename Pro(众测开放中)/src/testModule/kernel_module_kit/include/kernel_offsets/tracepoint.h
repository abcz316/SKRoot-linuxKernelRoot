#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {
/***************************************************************************
* 获取 tracepoint 结构体中 name 字段的偏移量（限 Linux >= 3.15.0）
* 参数: offset      输出参数，返回 name 字段相对于 tracepoint 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_tracepoint_name_offset(uint32_t & offset);

/***************************************************************************
* 获取 tracepoint 结构体中 funcs 字段的偏移量（限 Linux >= 3.15.0）
* 参数: offset      输出参数，返回 funcs 字段相对于 tracepoint 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_tracepoint_funcs_offset(uint32_t & offset);
}
