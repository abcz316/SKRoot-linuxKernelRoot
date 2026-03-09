#include "rootkit_command.h"
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

#include "rootkit_umbrella.h"
#include "rootkit_fork_helper.h"
#include "common/selinux_procattr_util.h"
#include "common/cgroup_v2_self.h"
#include "common/cgroup_v1_tasks_self.h"

namespace kernel_root {
KRootErr get_root(const char* str_root_key) {
	if (!str_root_key) return KRootErr::ERR_PARAM;
	if (!strlen(str_root_key)) return KRootErr::ERR_PARAM;
	std::string internel_key = str_root_key;
	internel_key.erase(internel_key.size() - 1);
	syscall(__NR_execve, internel_key.c_str(), NULL, NULL);
	if(getuid() != 0) return KRootErr::ERR_NO_ROOT;
    selinux_procattr::setcon("u:r:shell:s0");
    selinux_procattr::setexeccon("u:r:shell:s0");
	cg_v2::migrate_self_to_root();
	cg_v1::migrate_self_threads_v1(/*cpuset*/nullptr, /*stune*/nullptr);
	return KRootErr::OK;
}

KRootErr run_root_cmd_with_cb(const char* str_root_key, const char* cmd, void (*cb)(const char* result)) {
	if (str_root_key == NULL || cmd == NULL || strlen(cmd) == 0) return KRootErr::ERR_PARAM;

	KRootErr err = KRootErr::OK;

	std::string cmd_add_err_info = cmd;
	cmd_add_err_info += " 2>&1";

	std::string result;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		do {
			BREAK_ON_ERROR(get_root(str_root_key));
			FILE * fp = popen(cmd_add_err_info.c_str(), "r");
			if(!fp) {
				err = KRootErr::ERR_POPEN;
				break;
			}
			int pip = fileno(fp);
			while(true) {
				char rbuf[1024] = {0};
				ssize_t r = read(pip, rbuf, sizeof(rbuf));
				if (r == -1 && errno == EAGAIN) continue;
				else if(r > 0) { std::string str_convert(rbuf, r); result += str_convert; }
				else break;
			}
			pclose(fp);
		} while(0);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, result);
		finfo.close_all();
		_exit(0);
		return {};
	}

	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_string_from_child(finfo, result)) err = KRootErr::ERR_READ_CHILD_STRING;
	else cb(result.c_str());
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}
}
