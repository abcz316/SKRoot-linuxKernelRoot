#ifndef _PROCESS64_INJECT_H_
#define _PROCESS64_INJECT_H_
#include "testRoot.h"
#include <unistd.h>
#include <vector>


//注入64位进程远程执行命令
struct process64_env {
	char key[0x1000]; //key和name的值不能大于pagesize
	char value[0x1000];
};
std::string inject_process64_run_cmd_wrapper(
	const char* str_root_key,
	pid_t target_pid,
	const char *cmd,
	ssize_t & out_err,
	bool user_root_auth = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);
//fork安全版本（可用于安卓APP直接调用）
std::string safe_inject_process64_run_cmd_wrapper(
	const char* str_root_key,
	pid_t target_pid,
	const char *cmd,
	ssize_t & out_err,
	bool user_root_auth = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

//注入远程进程添加PATH变量路径
ssize_t inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path);

//注入64位进程动态链接库so
ssize_t inject_process64_so_wrapper(const char* str_root_key, pid_t target_pid, const char *p_target_so_path, const char* target_so_func_name);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process64_so_wrapper(const char* str_root_key, pid_t target_pid, const char *p_target_so_path, const char* target_so_func_name);


//注入远程进程执行exit
ssize_t inject_process_run_exit_wrapper(const char* str_root_key, int target_pid);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process_run_exit_wrapper(const char* str_root_key, int target_pid);


ssize_t kill_process(const char* str_root_key, pid_t pid);
ssize_t safe_kill_process(const char* str_root_key, pid_t pid);
#endif /* _PROCESS64_INJECT_H_ */
