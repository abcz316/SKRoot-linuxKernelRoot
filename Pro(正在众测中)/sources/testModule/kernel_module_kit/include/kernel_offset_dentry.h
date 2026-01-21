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
* 获取 dentry 结构体中 d_parent 字段的偏移量
* 参数: offset      输出参数，返回 d_parent 字段相对于 dentry 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_dentry_d_parent_offset(uint32_t & offset);

/***************************************************************************
* 获取 dentry 结构体中 d_name 字段的偏移量
* 参数: offset      输出参数，返回 d_name 字段相对于 dentry 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_dentry_d_name_offset(uint32_t & offset);

/***************************************************************************
* 获取 dentry 结构体中 d_inode 字段的偏移量
* 参数: offset      输出参数，返回 d_inode 字段相对于 dentry 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_dentry_d_inode_offset(uint32_t & offset);

/***************************************************************************
* 获取 dentry 结构体中 d_shortname 字段的偏移量（限 Linux >= 6.14.0）
* 参数: offset      输出参数，返回 d_shortname 字段相对于 dentry 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_dentry_d_shortname_offset(uint32_t & offset);

/***************************************************************************
* 获取 dentry 结构体中 d_iname 字段的偏移量（限 Linux < 6.14.0）
* 参数: offset      输出参数，返回 d_iname 字段相对于 dentry 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_dentry_d_iname_offset(uint32_t & offset);

}
