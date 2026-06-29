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
* 获取 file_operations 结构体中 llseek 函数指针的偏移量
* 参数: offset      输出参数，返回 llseek 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_llseek_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 read 函数指针的偏移量
* 参数: offset      输出参数，返回 read 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_read_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 write 函数指针的偏移量
* 参数: offset      输出参数，返回 write 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_write_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 read_iter 函数指针的偏移量
* 参数: offset      输出参数，返回 read_iter 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_read_iter_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 write_iter 函数指针的偏移量
* 参数: offset      输出参数，返回 write_iter 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_write_iter_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 iterate_shared 函数指针的偏移量
* 参数: offset      输出参数，返回 iterate_shared 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_iterate_shared_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 unlocked_ioctl 函数指针的偏移量
* 参数: offset      输出参数，返回 unlocked_ioctl 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_unlocked_ioctl_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 poll 函数指针的偏移量
* 参数: offset      输出参数，返回 poll 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_poll_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 mmap 函数指针的偏移量
* 参数: offset      输出参数，返回 mmap 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_mmap_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 open 函数指针的偏移量
* 参数: offset      输出参数，返回 open 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_open_offset(uint32_t & offset);

/***************************************************************************
* 获取 file_operations 结构体中 release 函数指针的偏移量
* 参数: offset      输出参数，返回 release 函数指针相对于 file_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_release_offset(uint32_t & offset);
}
