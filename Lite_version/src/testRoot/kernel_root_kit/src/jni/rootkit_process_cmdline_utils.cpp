#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <set>
#include <map>
#include <time.h>
#include "rootkit_umbrella.h"
#include "rootkit_fork_helper.h"

namespace kernel_root {
static KRootErr unsafe_find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc) {
	out.clear();
	RETURN_ON_ERROR(get_root(str_root_key));

	DIR* dir = opendir("/proc");
	if (dir == NULL) {
		return KRootErr::ERR_OPEN_DIR;
	}
	struct dirent * entry;
	while ((entry = readdir(dir)) != NULL) {
		std::string all_cmdline;
		char cmdline[1024] = {0};
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) continue;
		else if (entry->d_type != DT_DIR) continue;
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) continue;

		int pid = atoi(entry->d_name);
		if (pid == 0) continue;
		char filename[32] = {0};
		sprintf(filename, "/proc/%d/cmdline", pid);
		FILE *fp = fopen(filename, "r");
		if (!fp) continue;
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
			//printf("[+] find %d process cmdline: %s\n", id, cmdline);
			if (strcmp(cmdline, target_cmdline) == 0) {
				/* process found */
				out.insert(pid);
			}
		}
	}

	closedir(dir);
	return KRootErr::OK;
}

static KRootErr safe_find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr ret = unsafe_find_all_cmdline_process(str_root_key, target_cmdline, out, compare_full_agrc);
		write_errcode_from_child(finfo, ret);
		write_set_int_from_child(finfo, out);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	out.clear();
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_set_int_from_child(finfo, out)) err = KRootErr::ERR_READ_CHILD_SET_ARR;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr find_all_cmdline_process_with_cb(const char* str_root_key, const char* target_cmdline, void (*cb)(pid_t pid), bool compare_full_agrc) {
	std::set<pid_t> out_set;
	RETURN_ON_ERROR(safe_find_all_cmdline_process(str_root_key, target_cmdline, out_set, compare_full_agrc));
	for(auto p : out_set) {
		cb(p);
	}
	return KRootErr::OK;
}

static KRootErr unsafe_wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t & pid, bool compare_full_agrc) {
	pid = 0;
	RETURN_ON_ERROR(get_root(str_root_key));
	clock_t start = clock();
	while (1) {
		sleep(0);
		DIR*dir = opendir("/proc");
		if (dir == NULL) return KRootErr::ERR_OPEN_DIR;
		struct dirent * entry;
		while ((entry = readdir(dir)) != NULL) {
			if (pid > 0) break;
			std::string all_cmdline;
			char cmdline[1024] = {0};
			if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) continue;
			else if (entry->d_type != DT_DIR) continue;
			else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) continue;

			int old_pid = atoi(entry->d_name);
			if (old_pid == 0) continue;

			char filename[32] = {0};
			sprintf(filename, "/proc/%d/cmdline", old_pid);
			FILE *fp = fopen(filename, "r");
			if (!fp) continue;

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
				//printf("[+] find %d process cmdline: %s\n", id, cmdline);
				if (strcmp(cmdline, target_cmdline) == 0) {
					/* process found */
					pid = old_pid;
					break;
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
	return pid > 0 ? KRootErr::OK : KRootErr::ERR_PID_NOT_FOUND;
}

static KRootErr safe_wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t &pid, bool compare_full_agrc) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		pid_t pid;
		KRootErr ret = unsafe_wait_and_find_cmdline_process(str_root_key, target_cmdline, timeout, pid, compare_full_agrc);
		write_errcode_from_child(finfo, ret);
		write_int_from_child(finfo, pid);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_int_from_child(finfo, pid)) err = KRootErr::ERR_READ_CHILD_INT;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t &pid, bool compare_full_agrc) {
	return safe_wait_and_find_cmdline_process(str_root_key, target_cmdline, timeout, pid, compare_full_agrc);
}

static KRootErr unsafe_get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc) {
	char filename[32];
	struct dirent * entry;
	RETURN_ON_ERROR(get_root(str_root_key));
	pid_map.clear();
	DIR* dir = opendir("/proc");
	if (dir == NULL) return KRootErr::ERR_OPEN_DIR;
	while ((entry = readdir(dir)) != NULL) {
		std::string all_cmdline;
		char cmdline[1024] = {0};
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) continue;
		else if (entry->d_type != DT_DIR) continue;
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) continue;

		pid_t pid = atoi(entry->d_name);
		if (pid == 0) continue;
		sprintf(filename, "/proc/%d/cmdline", pid);
		FILE *fp = fopen(filename, "r");
		if (!fp) continue;

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
	closedir(dir);
	return pid_map.size() > 0 ? KRootErr::OK : KRootErr::ERR_PID_NOT_FOUND;
}

static KRootErr safe_get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc) {
	fork_pipe_info finfo;
	std::map<int, std::string> data;
	if(fork_pipe_child_process(finfo)) {
		KRootErr ret = unsafe_get_all_cmdline_process(str_root_key, pid_map, compare_full_agrc);
		for(auto & item : pid_map) {
			data[item.first] = item.second;
		}
		write_errcode_from_child(finfo, ret);
		write_map_i_s_from_child(finfo, data);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_map_i_s_from_child(finfo, data)) err = KRootErr::ERR_READ_CHILD_MAP_I_S;
	for(auto & item : data) pid_map[item.first] = item.second;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr get_all_cmdline_process_with_cb(const char* str_root_key, void (*cb)(pid_t pid, const char* cmdline), bool compare_full_agrc) {
	std::map<pid_t, std::string> pid_map;
	RETURN_ON_ERROR(safe_get_all_cmdline_process(str_root_key, pid_map, compare_full_agrc));
	for(auto& item : pid_map) {
		cb(item.first, item.second.c_str());
	}
	return KRootErr::OK;
}
}
