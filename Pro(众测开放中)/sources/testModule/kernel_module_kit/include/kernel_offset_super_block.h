#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {
/***************************************************************************
* 获取 super_block 结构体中 s_uuid 字段的偏移量
* 参数: offset      输出参数，返回 s_uuid 字段相对于 super_block 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_super_block_s_uuid_offset(uint32_t & offset);
}
