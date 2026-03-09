#pragma once
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <map>

namespace kernel_root {
/***************************************************************************
 * 查找所有符合指定 cmdline 字符串的进程 ID
 * 参数:
 *   str_root_key           ROOT 权限密钥文本
 *   target_cmdline         目标进程的 cmdline 字符串
 *   out                    输出，存放所有匹配到的进程 ID
 *   compare_full_agrc      是否完整匹配进程的cmdline
 *                         true:匹配完整的进程cmdline（所有参数），
 *                         false:只匹配进程cmdline的第一个参数（程序名）
 * 返回: OK 表示成功；其余为错误码
***************************************************************************/
KRootErr find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc = false);

/***************************************************************************
 * 等待并查找符合指定 cmdline 字符串的进程
 * 参数:
 *   str_root_key           ROOT 权限密钥文本
 *   target_cmdline         目标进程的 cmdline 字符串
 *   timeout                超时时间（秒）
 *   pid                    输出: 找到后设置为进程 ID；超时则保持为 0
 *   compare_full_agrc      是否完整匹配进程的cmdline
 *                         true:匹配完整的进程cmdline（所有参数），
 *                         false:只匹配进程cmdline的第一个参数（程序名）
 * 返回: OK 表示成功；其余为错误码
 ***************************************************************************/
KRootErr wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t & pid, bool compare_full_agrc = false);

/***************************************************************************
 * 获取所有进程的 PID 与 cmdline 映射
 * 参数:
 *   str_root_key        — ROOT 权限密钥文本
 *   pid_map             — 输出: 保存每个进程的 pid 及其 cmdline 字符串
 *   compare_full_agrc   — 是否读取完整参数列表并拼接：
 *                         true  — 拼接所有参数
 *                         false — 只保存第一个参数
 * 返回: OK 表示成功；其余为错误码
 ***************************************************************************/
KRootErr get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc = false);
}
