#ifndef KERNEL_ROOT_HELPER_H_
#define KERNEL_ROOT_HELPER_H_

#ifdef __linux__
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "safe_fork_helper.h"

namespace kernel_root {

	//获取ROOT权限，返回值为0则代表成功
	static inline ssize_t get_root(const char* str_root_key) {
		if (str_root_key == NULL) { return -100; }
		syscall(__NR_execve, str_root_key, NULL, NULL);
		return 0;
	}

	//检查系统SELinux的是否为禁用状态
	static bool is_disable_selinux_status() {
		int cnt = 0;
		DIR* dir = opendir("/");
		if (NULL != dir) {
			struct dirent* ptr = NULL;
			while ((ptr = readdir(dir)) != NULL) {
				if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
					continue;
				}
				cnt++;
			}
			closedir(dir);
		}
		return cnt > 3 ? true : false;
	}

	//执行root命令，返回值为0则代表成功
	static std::string run_root_cmd(const char* str_root_key, const char* cmd, ssize_t & err) {
		if (str_root_key == NULL || cmd == NULL || strlen(cmd) == 0) {
			err = 0;
			return {};
		}
		//把错误信息也打出来
		std::string cmd_add_err_info = cmd;
		cmd_add_err_info += " 2>&1";

		std::string result;
		fork_pipe_info finfo;
		if(fork_pipe_child_process(finfo)) {
			err = 0;
			do {
				if (get_root(str_root_key) != 0) {
					err = -110;
					break;
				}
				FILE * fp = popen(cmd_add_err_info.c_str(), "r");
				if(!fp) {
					err = -111;
					break;
				}
				int pip = fileno(fp);
				while(true) {
					char rbuf[1024] = {0};
					ssize_t r = read(pip, rbuf, sizeof(rbuf));
					if (r == -1 && errno == EAGAIN) {
						continue; //意味着现在没有可用的数据,以后再试一次
					} else if(r > 0) {
						std::string str_convert(rbuf, r);
						result += str_convert;
					} else {
						break;
					}
				}
				pclose(fp);
			} while(0);
			write_errcode_to_father(finfo, err);
			write_string_to_father(finfo, result);
			_exit(0);
			return 0;
		}
		err = 0;
		if(!wait_fork_child_process(finfo)) {
			err = -112;
		} else {
			if(!read_errcode_from_child(finfo, err)) {
				err = -113;
			} else if(!read_string_from_child(finfo, result)) {
				err = -114;
			}
		}
		return result;
	}
}

#endif /*__linux__*/


#endif /* KERNEL_ROOT_HELPER_H_ */
