#pragma once
#include <stdint.h>
#include "module_err_def.h"
#include "module_base_kernel_mem.h"
#include "module_base_linux_version.h"

namespace kernel_module {
// Linux 4.0 ~ 4.4：字段直接位于 struct module 中
namespace linux_4_0_0 {
/***************************************************************************
 * 获取 module 结构体中 module_core 字段的偏移量
 * 参数: offset     输出参数，返回 module_core 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_core_offset(uint32_t & offset);

/***************************************************************************
 * 获取 module 结构体中 core_text_size 字段的偏移量
 * 参数: offset     输出参数，返回 core_text_size 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_core_text_size_offset(uint32_t & offset);
} // namespace linux_4_0_0

// Linux 4.5 ~ 6.3：struct module -> core_layout(struct module_layout)
namespace linux_4_5_0 {
/***************************************************************************
 * 获取 module 结构体中 core_layout.base 字段的偏移量
 * 参数: offset     输出参数，返回 core_layout.base 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_core_layout_base_offset(uint32_t & offset);

/***************************************************************************
 * 获取 module 结构体中 core_layout.text_size 字段的偏移量
 * 参数: offset     输出参数，返回 core_layout.text_size 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_core_layout_text_size_offset(uint32_t & offset);
} // namespace linux_4_5_0

// Linux 6.4 ~ 6.18：struct module -> mem[MOD_TEXT](struct module_memory)
namespace linux_6_4_0 {
/***************************************************************************
 * 获取 module 结构体中 mem[MOD_TEXT].base 字段的偏移量
 * 参数: offset     输出参数，返回 mem[MOD_TEXT].base 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_mem_base_offset(uint32_t & offset);

/***************************************************************************
 * 获取 module 结构体中 mem[MOD_TEXT].size 字段的偏移量
 * 参数: offset     输出参数，返回 mem[MOD_TEXT].size 字段相对于 module 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_module_mem_size_offset(uint32_t & offset);
} // namespace linux_6_4_0

/***************************************************************************
 * 获取内核模块的text段的内存范围
 * 参数: struct_module_ptr  struct module * 的内核地址，由 export_symbol::find_module 返回
 *       out_start_kaddr    输出参数，返回 text 段起始地址
 *       out_end_kaddr      输出参数，返回 text 段结束地址（等于 start + text_size）
 * 返回: OK 表示成功；其它值为错误码
 *
 * 调用示例:
 *   uint64_t struct_module_ptr = 0;
 *   uint64_t start_kaddr = 0;
 *   uint64_t end_kaddr = 0;
 *   RETURN_IF_ERROR(export_symbol::find_module("vr", struct_module_ptr));
 *   if (!struct_module_ptr) return KModErr::ERR_MODULE_NOT_KADDR;   // 模块未加载
 *   RETURN_IF_ERROR(get_module_text_range(struct_module_ptr, start_kaddr, end_kaddr));
 ***************************************************************************/
inline KModErr get_module_text_range(uint64_t struct_module_ptr, uint64_t & out_start_kaddr, uint64_t & out_end_kaddr) {
    out_start_kaddr = 0;
    out_end_kaddr = 0;
    if (!struct_module_ptr) return KModErr::ERR_MODULE_PARAM;
    uint32_t base_offset = 0;
    uint32_t size_offset = 0;
    if (is_kernel_version_less("4.5.0")) {
        RETURN_IF_ERROR(linux_4_0_0::get_module_core_offset(base_offset));
        RETURN_IF_ERROR(linux_4_0_0::get_module_core_text_size_offset(size_offset));
    } else if (is_kernel_version_less("6.4.0")) {
        RETURN_IF_ERROR(linux_4_5_0::get_module_core_layout_base_offset(base_offset));
        RETURN_IF_ERROR(linux_4_5_0::get_module_core_layout_text_size_offset(size_offset));
    } else {
        RETURN_IF_ERROR(linux_6_4_0::get_module_mem_base_offset(base_offset));
        RETURN_IF_ERROR(linux_6_4_0::get_module_mem_size_offset(size_offset));
    }
    uint64_t start_kaddr = 0;
    uint32_t text_size = 0;
    RETURN_IF_ERROR(read_kernel_mem(struct_module_ptr + base_offset, &start_kaddr, static_cast<uint32_t>(sizeof(start_kaddr))));
    RETURN_IF_ERROR(read_kernel_mem(struct_module_ptr + size_offset, &text_size, static_cast<uint32_t>(sizeof(text_size))));
    if (!start_kaddr || !text_size) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (start_kaddr > UINT64_MAX - text_size) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    out_start_kaddr = start_kaddr;
    out_end_kaddr = start_kaddr + text_size;
    return KModErr::OK;
}

}
