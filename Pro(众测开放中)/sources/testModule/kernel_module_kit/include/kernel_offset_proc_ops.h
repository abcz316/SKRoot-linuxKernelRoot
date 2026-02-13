#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {
struct proc_ops_offsets {
    uint32_t proc_open_offset = 0;
    uint32_t proc_read_offset = 0;
    uint32_t proc_write_offset = 0;
    uint32_t proc_lseek_offset = 0;
    uint32_t proc_release_offset = 0;
    uint32_t proc_poll_offset = 0;
    uint32_t proc_mmap_offset = 0;
};

/***************************************************************************
* 获取 proc_ops 结构体中的字段偏移量 （限 Linux >= 5.6.0）
* 参数: offsets     输出参数，返回 proc_ops 结构体中的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_proc_ops_offsets(proc_ops_offsets& offsets);
}
