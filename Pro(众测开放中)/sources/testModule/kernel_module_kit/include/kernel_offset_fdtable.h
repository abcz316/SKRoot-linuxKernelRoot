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
* 获取 fdtable 结构体中 struct file __rcu **fd; 字段的偏移量
* 参数: offset      输出参数，返回 fd 字段相对于 fdtable 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_fdtable_fd_offset(uint32_t & offset);
}
