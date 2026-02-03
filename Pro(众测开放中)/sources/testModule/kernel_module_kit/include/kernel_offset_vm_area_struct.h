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
* 获取 mm_struct 结构体中 vm_start\vm_end 字段的偏移量
* 参数: vm_start_offset        输出参数，返回 vm_start 字段相对于 mm_struct 起始的偏移量（字节）
*       vm_end_offset      输出参数，返回 vm_end 字段相对于 mm_struct 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_vm_area_struct_vm_offset(uint32_t & vm_start_offset, uint32_t & vm_end_offset);

/***************************************************************************
* 获取 file 结构体中 vm_file 字段的偏移量
* 参数: offset      输出参数，返回 vm_file 字段相对于 file 起始的偏移量（字节）
* 返回: OK 表示成功；其它值为错误码
***************************************************************************/
KModErr get_vm_area_struct_vm_file_offset(uint32_t & offset);

}
