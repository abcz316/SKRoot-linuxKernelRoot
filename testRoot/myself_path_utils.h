#ifndef _MYSELF_PATH_UTILS_H_
#define _MYSELF_PATH_UTILS_H_
#include <unistd.h>

static size_t get_executable_path(char* processdir, char* processname, size_t len)
{
	char* path_end;
	if (readlink("/proc/self/exe", processdir, len) <= 0)
	{
		return -1;
	}
	path_end = strrchr(processdir, '/');
	if (path_end == NULL)
	{
		return -1;
	}
	++path_end;
	strcpy(processname, path_end);
	*path_end = '\0';
	return (size_t)(path_end - processdir);
}

#endif /* _MYSELF_PATH_UTILS_H_ */
