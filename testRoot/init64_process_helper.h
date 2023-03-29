#ifndef INIT64_HELPER_H_
#define INIT64_HELPER_H_
#include <unistd.h>
#include <thread>
#include <atomic>
#include "random_utils.h"
#include "process64_inject.h"
#include "process_cmdline_utils.h"


//注入init64进程远程执行命令
static std::string run_init64_cmd_wrapper(
	const char* str_root_key,
	const char *cmd,
	ssize_t & out_err) {
	pid_t target_pid = 1;
	std::string str_cmd_result;

	//让init64进程启动一个子进程
	char guid[32] = { 0 };
	rand_str(guid, sizeof(guid));
	std::string strGuid(guid, sizeof(guid));

	std::string fork_proc_cmd = "sleep 0.15";
	fork_proc_cmd += " --guid=";
	fork_proc_cmd += strGuid;

	std::atomic<bool> thread_exist{true};
	std::atomic<bool>* pthread_exist = &thread_exist;
	std::thread td_run_child_proc([&]()-> void {
		TRACE("init64 run child thread start.\n");
		pid_t child_pid;
		out_err = wait_and_find_cmdline_process(str_root_key, strGuid.c_str(), 1*1000, child_pid);
		TRACE("init64 run child err:%zd, pid:%d\n", out_err, child_pid);
		if(out_err == 0 && child_pid > 0) {
			//把错误信息也打出来
			std::string cmd_add_err_info = cmd;
			cmd_add_err_info += " 2>&1";
			str_cmd_result = inject_process64_run_cmd_wrapper(str_root_key, child_pid,
				cmd_add_err_info.c_str(), out_err, true);
			//inject_process_run_exit_wrapper(str_root_key, child_pid);
			kill_process(str_root_key, child_pid);
			TRACE("init64 run child cmd result:%s\n", str_cmd_result.c_str());
		}
		*pthread_exist = false;
	});
	td_run_child_proc.detach(); //因为运行子进程的时候父进程会一直阻塞，所以这里启动一条新的线程去读子进程

	TRACE("init64 run child thread cmd:%s\n", fork_proc_cmd.c_str());
	inject_process64_run_cmd_wrapper(str_root_key, target_pid,
											fork_proc_cmd.c_str(), out_err, false);
	if(out_err != 0) {
		return {};
	}
	TRACE("init64 run child successfully.\n");
	
	while(thread_exist) {
		sleep(0);
	}
	return str_cmd_result;
}

//fork安全版本（可用于安卓APP直接调用）
static std::string safe_run_init64_cmd_wrapper(
	const char* str_root_key,
	const char *cmd,
	ssize_t & out_err) {
	pid_t target_pid = 1;
	return safe_inject_process64_run_cmd_wrapper(str_root_key, target_pid,
												 cmd, out_err);
}
#endif /* INIT64_HELPER_H_ */
