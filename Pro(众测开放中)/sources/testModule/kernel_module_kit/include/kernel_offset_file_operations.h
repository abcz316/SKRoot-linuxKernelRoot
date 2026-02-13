#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {
struct file_operations_offsets {
    uint32_t llseek_offset = 0;
    uint32_t read_offset = 0;
    uint32_t write_offset = 0;
    uint32_t read_iter_offset = 0;
    uint32_t write_iter_offset = 0;
    uint32_t poll_offset = 0;
    uint32_t unlocked_ioctl_offset = 0;
    uint32_t mmap_offset = 0;
    uint32_t open_offset = 0;
    uint32_t release_offset = 0;
};

/***************************************************************************
* 获取 file_operations 结构体中的字段偏移量
* 参数: offsets     输出参数，返回 file_operations 结构体中的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_file_operations_offsets(file_operations_offsets& offsets);
}
