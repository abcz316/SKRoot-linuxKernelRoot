#ifndef _KERNEL_ROOT_KIT__PROCESS64_INJECT_H_
#define _KERNEL_ROOT_KIT__PROCESS64_INJECT_H_
#include <unistd.h>
#include <vector>

namespace kernel_root {

enum class api_offset_read_mode {
	only_read_file,
	only_read_myself_mem,
	all
};

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
	std::vector<process64_env> *set_env = NULL,
	api_offset_read_mode api_mode = api_offset_read_mode::all);
//fork安全版本（可用于安卓APP直接调用）
std::string safe_inject_process64_run_cmd_wrapper(
	const char* str_root_key,
	pid_t target_pid,
	const char *cmd,
	ssize_t & out_err,
	bool user_root_auth = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL,
	api_offset_read_mode api_mode = api_offset_read_mode::all);

//注入远程进程添加PATH变量路径
ssize_t inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path,
	api_offset_read_mode api_mode = api_offset_read_mode::all);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path,
	api_offset_read_mode api_mode = api_offset_read_mode::all);

ssize_t kill_process(const char* str_root_key, pid_t pid);
ssize_t safe_kill_process(const char* str_root_key, pid_t pid);
}
#endif /* _KERNEL_ROOT_KIT__PROCESS64_INJECT_H_ */
