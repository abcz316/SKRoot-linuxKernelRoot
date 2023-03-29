#ifndef PROCESS_CMDLINE_UTILS_H_
#define PROCESS_CMDLINE_UTILS_H_
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <vector>
#include <time.h>
#include "kernel_root_helper.h"
#include "kernel_root_key.h"

static ssize_t find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::vector<pid_t> & vOut)
{
	int pid;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;
	vOut.clear();
	if (kernel_root::get_root(str_root_key) != 0) {
		return -1000001;
	}

	dir = opendir("/proc");
	if (dir == NULL) {
		return -1000002;
	}
	while ((entry = readdir(dir)) != NULL) {
		// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
			continue;
		}

		pid = atoi(entry->d_name);
		if (pid != 0) {
			sprintf(filename, "/proc/%d/cmdline", pid);
			fp = fopen(filename, "r");
			if (fp) {
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);
				//TRACE("[+] find %d process cmdline: %s\n", id, cmdline);
				if (strstr(cmdline, target_cmdline)) {
					/* process found */
					vOut.push_back(pid);
				}
			}
		}
	}

	closedir(dir);
	return 0;
}

static ssize_t safe_find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::vector<pid_t> & vOut)
{
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = find_all_cmdline_process(str_root_key, target_cmdline, vOut);
		std::vector<int> vec_pid;
		for (pid_t t : vOut) {
			vec_pid.push_back(t);
		}
		write_errcode_to_father(finfo, ret);
		write_vec_int_to_father(finfo, vec_pid);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -1000011;
	} else {
		std::vector<int> vec_pid;
		if(!read_errcode_from_child(finfo, err)) {
			err = -1000012;
		} else if(!read_vec_int_from_child(finfo, vec_pid)) {
			err = -1000013;
		}
		for (int pid : vec_pid) {
			vOut.push_back(pid);
		}
	}
	return err;
}

static ssize_t wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t & pid)
{
	int old_pid;
	int fd;
	size_t length;
	DIR* dir;
	char filename[32];
	char arg_list[1024];
	char* next_arg;
	std::string all_cmdline;

	struct dirent * entry;
	pid = 0;
	if (kernel_root::get_root(str_root_key) != 0) {
		return -1000021;
	}
	clock_t start = clock();
	while (1) {
		sleep(0);

		dir = opendir("/proc");
		if (dir == NULL) {
			return -1000022;
		}

		while ((entry = readdir(dir)) != NULL) {
			// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
			if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
				continue;
			}
			else if (entry->d_type != DT_DIR) {
				continue;
			}
			else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
				continue;
			}

			old_pid = atoi(entry->d_name);
			if (old_pid != 0) {
				sprintf(filename, "/proc/%d/cmdline", old_pid);
				fd = open(filename, O_RDONLY);
				if (fd >= 0) {
					length = read (fd, arg_list, sizeof (arg_list));
					close(fd);
					/* read does not NUL-terminate the buffer, so do it here. */
					arg_list[length] = '\0';

					next_arg = arg_list;
					
					while (next_arg < arg_list + length) {
						/* Print the argument. Each is NUL-terminated,
							* so just treat it like an ordinary string.
							*/
						//
						if(!all_cmdline.empty()) {
							all_cmdline += " ";
						}
						all_cmdline+=next_arg;
						/* Advance to the next argument. Since each argument is NUL-terminated,
						* strlen counts the length of the next argument, not the entire argument list.
						*/
						next_arg += strlen (next_arg) + 1;
					}
					//printf("[+] find %d process arg: %s\n", old_pid, all_cmdline.c_str());
					if(all_cmdline.find(target_cmdline) != -1) {
						/* process found */
						pid = old_pid;
						break;
					}
				}
			}
		}
		closedir(dir);
		if (pid > 0) {
			break;
		}
		clock_t finish = clock();
		double total_time = (double)(finish - start) / CLOCKS_PER_SEC;
		if(total_time >= timeout) {
			break;
		}
	}
	return pid > 0 ? 0 : -1000023;
}

static ssize_t safe_wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t &pid)
{
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		pid_t pid;
		ssize_t ret = wait_and_find_cmdline_process(str_root_key, target_cmdline, timeout, pid);
		write_errcode_to_father(finfo, ret);
		write_int_to_father(finfo, pid);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -1000031;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -1000032;
		} else if(!read_int_from_child(finfo, pid)) {
			err = -1000033;
		}
	}
	return err;
}

#endif /* PROCESS_CMDLINE_UTILS_H_ */
