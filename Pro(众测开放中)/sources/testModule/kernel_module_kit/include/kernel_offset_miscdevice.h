#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MISC_DYNAMIC_MINOR	255

namespace kernel_module {
struct miscdevice_offsets {
    uint32_t minor_offset = 0;
    uint32_t name_offset = 0;
    uint32_t fops_offset = 0;
    uint32_t list_offset = 0;
};

/***************************************************************************
* 获取 miscdevice 结构体中的字段偏移量
* 参数: offsets     输出参数，返回 miscdevice 结构体中的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_miscdevice_offsets(miscdevice_offsets& offsets);
}
