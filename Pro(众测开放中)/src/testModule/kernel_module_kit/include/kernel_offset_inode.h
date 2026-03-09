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
* 获取 inode 结构体中 i_sb 字段的偏移量
* 参数: offset      输出参数，返回 i_sb 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_sb_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_mapping 字段的偏移量
* 参数: offset      输出参数，返回 i_mapping 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_mapping_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_ino 字段的偏移量
* 参数: offset      输出参数，返回 i_ino 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_ino_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_size 字段的偏移量
* 参数: offset      输出参数，返回 i_size 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_size_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_atime/i_mtime/i_ctime 字段的偏移量（限 Linux >= 6.11.0）
* 参数: offset      输出参数，返回 i_atime/i_mtime/i_ctime 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_time_offset(uint32_t & i_atime_sec_offset, uint32_t & i_atime_nsec_offset,
    uint32_t & i_mtime_sec_offset, uint32_t & i_mtime_nsec_offset,
    uint32_t & i_ctime_sec_offset, uint32_t & i_ctime_nsec_offset);

/***************************************************************************
* 获取 inode 结构体中 i_atime/i_mtime/i_ctime 字段的偏移量（限 Linux < 6.11.0）
* 参数: offset      输出参数，返回 i_atime/i_mtime/i_ctime 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_time_offset(uint32_t & i_atime_offset, uint32_t & i_mtime_offset, uint32_t & i_ctime_offset);

/***************************************************************************
* 获取 inode 结构体中 i_state 字段的偏移量
* 参数: offset      输出参数，返回 i_state 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_state_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_rwsem 字段的偏移量（限 Linux >= 4.7.0）
* 参数: offset      输出参数，返回 i_rwsem 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_rwsem_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode 结构体中 i_mutex 字段的偏移量（限 Linux < 4.7.0）
* 参数: offset      输出参数，返回 i_mutex 字段相对于 inode 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_i_mutex_offset(uint32_t & offset);

}
