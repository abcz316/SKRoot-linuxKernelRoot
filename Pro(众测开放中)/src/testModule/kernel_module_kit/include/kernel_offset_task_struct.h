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
 * 获取 task_struct 结构体中 struct mm_struct *mm 字段的偏移量
 * 参数: offset     输出参数，返回 mm 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK        表示调用成功；其他值为错误码
 ***************************************************************************/
KModErr get_task_struct_mm_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 pid 字段的偏移量
 * 参数: offset     输出参数，返回 pid 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_task_struct_pid_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 real_parent 字段的偏移量
 * 参数: offset     输出参数，返回 real_parent 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_task_struct_real_parent_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 comm 字段的偏移量
 * 参数: offset     输出参数，返回 comm 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_task_struct_comm_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 real_cred/cred 字段的偏移量
 * 参数: offset     输出参数，返回 real_cred/cred 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_task_struct_real_cred_offset(uint32_t & offset);
KModErr get_task_struct_cred_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 seccomp 字段的偏移量
 * 参数: offset     输出参数，返回 seccomp 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK        表示调用成功；其他值为错误码
 ***************************************************************************/
KModErr get_task_struct_seccomp_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 struct list_head tasks 字段的偏移量
 * 参数: offset     输出参数，返回 tasks 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK        表示调用成功；其他值为错误码
 ***************************************************************************/
KModErr get_task_struct_tasks_offset(uint32_t & offset);

/***************************************************************************
 * 获取 task_struct 结构体中 struct files_struct *files 字段的偏移量
 * 参数: offset     输出参数，返回 files 字段相对于 task_struct 起始的偏移量（字节）
 * 返回: OK        表示调用成功；其他值为错误码
 ***************************************************************************/
KModErr get_task_struct_files_offset(uint32_t & offset);

/***************************************************************************
 * 判断当前内核是否启用了 CONFIG_THREAD_INFO_IN_TASK 配置
 * 说明: 当启用该配置时，thread_info 内嵌在 task_struct 起始处，获取当前进程 task_struct* 可以直接通过 SP_EL0。
 * 返回: true  表示内核已启用 CONFIG_THREAD_INFO_IN_TASK
 *       false 表示内核未启用该配置（仍需通过 thread_info->task 获取）
 ***************************************************************************/
bool is_CONFIG_THREAD_INFO_IN_TASK();

/***************************************************************************
 * 设置当前进程的 COMM 名称
 * 参数: comm_name      要设置的进程 COMM 名（仅前 15 字节有效，结尾自动补 '\0'）
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr set_current_process_name(const char* comm_name);
}
