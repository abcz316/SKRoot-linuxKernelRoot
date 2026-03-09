#pragma once
#include <unistd.h>
#include <vector>

#include "rootkit_err_def.h"
namespace kernel_root {
enum class ApiOffsetReadMode: int {
    OnlyReadFile = 0,
    OnlyReadSelfMem,
    ReadAll,
};

/***************************************************************************
 * 向 64 位远程进程的 PATH 环境变量添加路径
 * 参数:
 *   str_root_key		ROOT 权限密钥文本
 *   target_pid			目标进程 PID
 *   add_path			要追加到 PATH 的路径字符串
 *   api_offset_mode	API偏移读取模式
 * 返回: OK 表示成功；其余为错误码
 ***************************************************************************/
KRootErr inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path,
	ApiOffsetReadMode api_offset_mode = ApiOffsetReadMode::ReadAll);

/***************************************************************************
 * 杀死指定进程
 * 参数:
 *   str_root_key	ROOT 权限密钥文本
 *   pid			要终止的进程 ID
 * 返回: OK 表示成功；其余为错误码
 ***************************************************************************/
KRootErr kill_process(const char* str_root_key, pid_t pid);
}