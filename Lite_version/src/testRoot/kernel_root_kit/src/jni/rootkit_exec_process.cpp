#include "rootkit_exec_process.h"
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include "rootkit_umbrella.h"
#include "rootkit_fork_helper.h"

namespace kernel_root {
	static KRootErr unsafe_root_exec_process(const char* str_root_key, const char *file_path) {
		if (file_path == NULL || strlen(file_path) == 0) return KRootErr::ERR_PARAM;

		RETURN_ON_ERROR(get_root(str_root_key));

		char *buf1 = strdup(file_path);
		size_t argc = 0;
		char *saveptr;
		for (char *tok = strtok_r(buf1, " ", &saveptr);
			tok;
			tok = strtok_r(NULL, " ", &saveptr)) {
			argc++;
		}
		free(buf1);

		char *buf2 = strdup(file_path);
		char **argv = static_cast<char**>(calloc(argc + 1, sizeof(char*)));
		size_t idx = 0;
		for (char *tok = strtok_r(buf2, " ", &saveptr);
			tok;
			tok = strtok_r(NULL, " ", &saveptr)) {
			argv[idx++] = tok;
		}
		argv[idx] = NULL;
		execve(argv[0], argv, environ);
		free(argv);
		free(buf2);
		return KRootErr::ERR_EXECVE;
	}

	static KRootErr safe_root_exec_process(
		const char* str_root_key,
		const char *file_path) {
		if (file_path == NULL || strlen(file_path) == 0) return KRootErr::ERR_PARAM;
		
		fork_pipe_info finfo;
		if (fork_pipe_child_process(finfo)) {
			KRootErr err = unsafe_root_exec_process(str_root_key, file_path);
			write_errcode_from_child(finfo, err);
			finfo.close_all();
			_exit(0);
			return KRootErr::OK;
		}
		KRootErr err = KRootErr::OK;
		if (!read_errcode_from_child(finfo, err)) {
			if(err == KRootErr::ERR_READ_EOF) err = KRootErr::OK;
		}
		int status = 0; waitpid(finfo.child_pid, &status, 0);
		return err;
	}

	KRootErr root_exec_process(
		const char* str_root_key,
		const char *file_path) {
		return safe_root_exec_process(str_root_key, file_path);
	}

}
