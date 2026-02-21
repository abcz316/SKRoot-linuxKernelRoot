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
* 获取 file 结构体中 struct path f_path; 字段的偏移量
* 参数: offset      输出参数，返回 f_path 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_f_path_offset(uint32_t & offset);

/***************************************************************************
* 获取 file 结构体中 struct inode *f_inode; 字段的偏移量
* 参数: offset      输出参数，返回 f_inode 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_f_inode_offset(uint32_t & offset);

/***************************************************************************
* 获取 file 结构体中 struct file_operations	*f_op; 字段的偏移量
* 参数: offset      输出参数，返回 f_op 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_f_op_offset(uint32_t & offset);

/***************************************************************************
* 获取 file 结构体中 struct cred *f_cred; 字段的偏移量
* 参数: offset      输出参数，返回 f_cred 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_f_cred_offset(uint32_t & offset);

/***************************************************************************
* 获取 file 结构体中 void* private_data; 字段的偏移量
* 参数: offset      输出参数，返回 private_data 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_private_data_offset(uint32_t & offset);
}
