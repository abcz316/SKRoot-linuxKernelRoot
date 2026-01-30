#include "exec_process.h"
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

#include "fork_helper.h"
#include "command.h"

static bool unsafe_root_exec_process(const char* str_root_key, const char *file_path) {
	if (file_path == NULL || strlen(file_path) == 0) return false;

	if(!get_root(str_root_key)) return false;

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
	return false;
}

static bool safe_root_exec_process(
	const char* str_root_key,
	const char *file_path) {
	if (file_path == NULL || strlen(file_path) == 0) return false;
	
	fork_pipe_info finfo;
	if (fork_pipe_child_process(finfo)) {
		bool success = unsafe_root_exec_process(str_root_key, file_path);
		write_bool_from_child(finfo, success);
		finfo.close_all();
		_exit(0);
		return false;
	}
	bool success = true;
	if (read_bool_from_child(finfo, success)) success = false;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return success;
}

bool root_exec_process(
	const char* str_root_key,
	const char *file_path) {
	return safe_root_exec_process(str_root_key, file_path);
}

