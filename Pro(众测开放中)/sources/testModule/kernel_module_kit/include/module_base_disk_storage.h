#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <errno.h>
#include "module_err_def.h"

namespace kernel_module {
/***************************************************************************
 * 写入磁盘持久化存储（按模块隔离）
 * 参数: key			键名称
 *      value		要写入的值
 * 说明: 模块之间相互隔离，即使其他模块使用了相同的 key，也不会相互干扰。
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
// 标量类型
KModErr write_bool_disk_storage   (const char* key, bool    value);
KModErr write_int8_disk_storage   (const char* key, int8_t  value);
KModErr write_uint8_disk_storage  (const char* key, uint8_t value);
KModErr write_int32_disk_storage  (const char* key, int32_t value);
KModErr write_uint32_disk_storage (const char* key, uint32_t value);
KModErr write_int64_disk_storage  (const char* key, int64_t value);
KModErr write_uint64_disk_storage (const char* key, uint64_t value);
KModErr write_float_disk_storage  (const char* key, float   value);
KModErr write_double_disk_storage (const char* key, double  value);

// 字符串 / 二进制
KModErr write_string_disk_storage (const char* key, const char* value);
KModErr write_blob_disk_storage   (const char* key, const void* data, uint64_t size);

/***************************************************************************
 * 读取磁盘持久化存储（按模块隔离）
 * 参数: key			键名称
 *      out			输出参数，存放读取到的值
 * 说明: 模块之间相互隔离，即使其他模块使用了相同的 key，也不会相互干扰。
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
// 标量类型
KModErr read_bool_disk_storage   (const char* key, bool&    out);
KModErr read_int8_disk_storage   (const char* key, int8_t&  out);
KModErr read_uint8_disk_storage  (const char* key, uint8_t& out);
KModErr read_int32_disk_storage  (const char* key, int32_t& out);
KModErr read_uint32_disk_storage (const char* key, uint32_t& out);
KModErr read_int64_disk_storage  (const char* key, int64_t& out);
KModErr read_uint64_disk_storage (const char* key, uint64_t& out);
KModErr read_float_disk_storage  (const char* key, float&   out);
KModErr read_double_disk_storage (const char* key, double&  out);

// 字符串 / 二进制
KModErr read_string_disk_storage (const char* key, std::string& out);
KModErr read_blob_disk_storage   (const char* key, std::vector<uint8_t>& out);

}
