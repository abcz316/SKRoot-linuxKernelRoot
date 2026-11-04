#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {
enum {
    LAST_NORM   = 0, // 普通文件名
    LAST_ROOT   = 1, // 根目录
    LAST_DOT    = 2, // 当前目录 .
    LAST_DOTDOT = 3  // 父目录 ..
};
struct qstr {
    union {
        struct {
            uint32_t hash;
            uint32_t len;
        };
        uint64_t hash_len;
    };
    const unsigned char* name;
};

/***************************************************************************
* 获取 nameidata 结构体中 struct qstr last; 字段的偏移量（不依赖 BTF / 内核头文件）
* 参数: last_offset        输出参数，返回 last 字段相对于 nameidata 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_nameidata_last_offset(uint32_t & last_offset);

/***************************************************************************
* 获取 nameidata 结构体中 int last_type; 字段的偏移量（不依赖 BTF / 内核头文件）
* 参数: last_type_offset        输出参数，返回 last_type 字段相对于 nameidata 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_nameidata_last_type_offset(uint32_t & last_type_offset);
}
