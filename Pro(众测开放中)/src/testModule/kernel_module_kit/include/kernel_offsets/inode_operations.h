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
* 获取 inode_operations 结构体中 lookup 函数指针的偏移量
* 参数: offset      输出参数，返回 lookup 函数指针相对于 inode_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_lookup_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode_operations::lookup函数类型的 KCFI 哈希值。
* 动态生成 lookup 回调时，需要把这个 32-bit的 KCFI 哈希值放在函数代码前面：
*     [ KCFI 哈希值 ][ function body ... ]
* 如果没有这个哈希值，内核调用时可能会死机。
*
* 参数: out_hash    输出参数，返回 lookup 函数原型对应的 KCFI 哈希值。
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_lookup_kcfi_hash(uint32_t& out_hash);

/***************************************************************************
* 获取 inode_operations 结构体中 permission 函数指针的偏移量
* 参数: offset      输出参数，返回 permission 函数指针相对于 inode_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_permission_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode_operations::permission函数类型的 KCFI 哈希值。
* 动态生成 permission 回调时，需要把这个 32-bit的 KCFI 哈希值放在函数代码前面：
*     [ KCFI 哈希值 ][ function body ... ]
* 如果没有这个哈希值，内核调用时可能会死机。
*
* 参数: out_hash    输出参数，返回 permission 函数原型对应的 KCFI 哈希值。
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_permission_kcfi_hash(uint32_t& out_hash);

/***************************************************************************
* 获取 inode_operations 结构体中 getattr 函数指针偏移量
* 参数: offset      输出参数，返回 getattr 函数指针相对于 inode_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_getattr_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode_operations::getattr函数类型的 KCFI 哈希值。
* 动态生成 getattr 回调时，需要把这个 32-bit的 KCFI 哈希值放在函数代码前面：
*     [ KCFI 哈希值 ][ function body ... ]
* 如果没有这个哈希值，内核调用时可能会死机。
*
* 参数: out_hash    输出参数，返回 getattr 函数原型对应的 KCFI 哈希值。
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_getattr_kcfi_hash(uint32_t& out_hash);

/***************************************************************************
* 获取 inode_operations 结构体中 setattr 函数指针偏移量
* 参数: offset      输出参数，返回 setattr 函数指针相对于 inode_operations 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_setattr_offset(uint32_t & offset);

/***************************************************************************
* 获取 inode_operations::setattr函数类型的 KCFI 哈希值。
* 动态生成 getattr 回调时，需要把这个 32-bit的 KCFI 哈希值放在函数代码前面：
*     [ KCFI 哈希值 ][ function body ... ]
* 如果没有这个哈希值，内核调用时可能会死机。
*
* 参数: out_hash    输出参数，返回 setattr 函数原型对应的 KCFI 哈希值。
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_inode_operations_setattr_kcfi_hash(uint32_t& out_hash);
}
