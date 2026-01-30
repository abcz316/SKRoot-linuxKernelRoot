#include "command.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/prctl.h>

#include "fork_helper.h"
#include "kernel_module_kit_umbrella.h"

bool get_root(const char* str_root_key) {
	if (!str_root_key) return false;
	if (!strlen(str_root_key)) return false;
	if(is_failed(skroot_env::get_root(str_root_key))) return false;
	return true;
}

bool run_root_cmd(const char* str_root_key, const char* cmd, std::string & out_result) {
	if (str_root_key == NULL || cmd == NULL || strlen(cmd) == 0) return false;

	bool success = true;

	std::string cmd_add_err_info = cmd;
	cmd_add_err_info += " 2>&1";

	std::string result;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		success = false;
		do {
			if(!get_root(str_root_key)) break;
			FILE * fp = popen(cmd_add_err_info.c_str(), "r");
			if(!fp) break;
			int pip = fileno(fp);
			while(true) {
				char rbuf[1024] = {0};
				ssize_t r = read(pip, rbuf, sizeof(rbuf));
				if (r == -1 && errno == EAGAIN) continue;
				else if(r > 0) { std::string str_convert(rbuf, r); result += str_convert; }
				else break;
			}
			pclose(fp);
			success = true;
		} while(0);
		write_bool_from_child(finfo, success);
		write_string_from_child(finfo, result);
		finfo.close_all();
		_exit(0);
		return {};
	}

	if(!read_bool_from_child(finfo, success)) success = false;
	else if(!read_string_from_child(finfo, result)) success = false;
	else out_result = result;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return success;
}
