#ifndef _KERNEL_ROOT_KIT_PROCESS_CMDLINE_UTILS_H_
#define _KERNEL_ROOT_KIT_PROCESS_CMDLINE_UTILS_H_
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <set>
#include <map>
#include <time.h>
#include "kernel_root_kit_command.h"

namespace kernel_root {
static ssize_t find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc = false)
{
	out.clear();
	if (kernel_root::get_root(str_root_key) != 0) {
		return -1000001;
	}

	DIR* dir = opendir("/proc");
	if (dir == NULL) {
		return -1000002;
	}
	struct dirent * entry;
	while ((entry = readdir(dir)) != NULL) {
		std::string all_cmdline;
		char cmdline[256] = {0};
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
			continue;
		}

		int pid = atoi(entry->d_name);
		if (pid != 0) {
			char filename[32] = {0};
			sprintf(filename, "/proc/%d/cmdline", pid);
			FILE *fp = fopen(filename, "r");
			if (fp) {
				if(compare_full_agrc) {
					char arg_list[1024] = {0};
					size_t length = fread(arg_list, 1, sizeof(arg_list), fp);
					/* read does not NUL-terminate the buffer, so do it here. */
					arg_list[length] = '\0';

					char*next_arg = arg_list;
					
					while (next_arg < arg_list + length) {
						/* Print the argument. Each is NUL-terminated,
							* so just treat it like an ordinary string.
							*/
						//
						if(!all_cmdline.empty()) {
							all_cmdline += " ";
						}
						all_cmdline += next_arg;
						/* Advance to the next argument. Since each argument is NUL-terminated,
						* strlen counts the length of the next argument, not the entire argument list.
						*/
						next_arg += strlen (next_arg) + 1;
					}
					//printf("[+] find %d process arg: %s\n", old_pid, all_cmdline.c_str());
					if(all_cmdline.find(target_cmdline) != -1) {
						/* process found */
						out.insert(pid);
					}
				} else {
					fgets(cmdline, sizeof(cmdline), fp);
					fclose(fp);
					//ROOT_PRINTF("[+] find %d process cmdline: %s\n", id, cmdline);
					if (strcmp(cmdline, target_cmdline) == 0) {
						/* process found */
						out.insert(pid);
					}
				}
				
			}
		}
	}

	closedir(dir);
	return 0;
}

static ssize_t safe_find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc = false)
{
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = find_all_cmdline_process(str_root_key, target_cmdline, out, compare_full_agrc);
		write_errcode_from_child(finfo, ret);
		write_set_int_from_child(finfo, out);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -1000011;
	} else {
		out.clear();
		if(!read_errcode_from_child(finfo, err)) {
			err = -1000012;
		} else if(!read_set_int_from_child(finfo, out)) {
			err = -1000013;
		}
	}
	return err;
}

static ssize_t wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t & pid, bool compare_full_agrc = false)
{
	pid = 0;
	if (kernel_root::get_root(str_root_key) != 0) {
		return -1000021;
	}
	clock_t start = clock();
	while (1) {
		sleep(0);
		DIR*dir = opendir("/proc");
		if (dir == NULL) {
			return -1000022;
		}
		struct dirent * entry;

		while ((entry = readdir(dir)) != NULL) {
			std::string all_cmdline;
			char cmdline[256] = {0};
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

			int old_pid = atoi(entry->d_name);
			if (old_pid != 0) {
				char filename[32] = {0};
				sprintf(filename, "/proc/%d/cmdline", old_pid);
				FILE *fp = fopen(filename, "r");
				if (fp) {
					if(compare_full_agrc) {
						char arg_list[1024] = {0};
						size_t length = fread(arg_list, 1, sizeof(arg_list), fp);
						fclose(fp);
						/* read does not NUL-terminate the buffer, so do it here. */
						arg_list[length] = '\0';

						char* next_arg = arg_list;
						while (next_arg < arg_list + length) {
							/* Print the argument. Each is NUL-terminated,
								* so just treat it like an ordinary string.
								*/
							//
							if(!all_cmdline.empty()) {
								all_cmdline += " ";
							}
							all_cmdline += next_arg;
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
					} else {
						fgets(cmdline, sizeof(cmdline), fp);
						fclose(fp);
						//ROOT_PRINTF("[+] find %d process cmdline: %s\n", id, cmdline);
						if (strcmp(cmdline, target_cmdline) == 0) {
							/* process found */
							pid = old_pid;
							break;
						}
					}
					
				}
			}
			if (pid > 0) {
				break;
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

static ssize_t safe_wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t &pid, bool compare_full_agrc = false)
{
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		pid_t pid;
		ssize_t ret = wait_and_find_cmdline_process(str_root_key, target_cmdline, timeout, pid, compare_full_agrc);
		write_errcode_from_child(finfo, ret);
		write_int_from_child(finfo, pid);
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


static ssize_t get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc = false)
{
	DIR* dir;
	char filename[32];

	struct dirent * entry;
	pid_map.clear();
	if (kernel_root::get_root(str_root_key) != 0) {
		return -1000041;
	}
	dir = opendir("/proc");
	if (dir == NULL) {
		return -1000042;
	}
	while ((entry = readdir(dir)) != NULL) {
		std::string all_cmdline;
		char cmdline[256] = {0};
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
			continue;
		}

		pid_t pid = atoi(entry->d_name);
		if (pid != 0) {
			sprintf(filename, "/proc/%d/cmdline", pid);
			FILE *fp = fopen(filename, "r");
			if (fp) {
				if(compare_full_agrc) {
					char arg_list[1024] = {0};
					size_t length = fread(arg_list, 1, sizeof(arg_list), fp);
					fclose(fp);
					/* read does not NUL-terminate the buffer, so do it here. */
					arg_list[length] = '\0';

					char* next_arg = arg_list;

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
					pid_map[pid] = all_cmdline;
				} else {
					fgets(cmdline, sizeof(cmdline), fp);
					fclose(fp);
					pid_map[pid] = cmdline;
				}

			}
		}
	}
	return pid_map.size() > 0 ? 0 : -1000043;
}

static ssize_t safe_get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc = false)
{
	fork_pipe_info finfo;
	std::map<int, std::string> data;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = get_all_cmdline_process(str_root_key, pid_map, compare_full_agrc);
		for(auto & item : pid_map) {
			data[item.first] = item.second;
		}
		write_errcode_from_child(finfo, ret);
		write_map_i_s_from_child(finfo, data);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -1000051;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -1000052;
		} else if(!read_map_i_s_from_child(finfo, data)) {
			err = -1000053;
		}
		for(auto & item : data) {
			pid_map[item.first] = item.second;
		}
	}
	return err;
}

}

#endif /* _KERNEL_ROOT_KIT_PROCESS_CMDLINE_UTILS_H_ */
