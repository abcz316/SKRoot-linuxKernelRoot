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
* 获取 file_struct 结构体中 struct fdtable __rcu *fdt; 字段的偏移量
* 参数: offset      输出参数，返回 fdt 字段相对于 file_struct 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_struct_fdt_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_struct 结构体中 struct fdtable fdtab; 字段的偏移量
* 参数: offset      输出参数，返回 fdtab 字段相对于 file_struct 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_struct_fdtab_offset(uint32_t & offset);
}
