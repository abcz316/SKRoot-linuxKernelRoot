#ifndef _KERNEL_ROOT_KIT_MAPS_HELPER_H_
#define _KERNEL_ROOT_KIT_MAPS_HELPER_H_
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <set>
#include <filesystem>

namespace kernel_root {
static std::string find_process_libc_so_path(pid_t pid) {
	char line[1024] = { 0 };
	std::string so_path;
	char filename[32];
	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}
	FILE* fp = fopen(filename, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "libc.so")) {

				char* start = strstr(line, "/");
				if (start) {
					start[strlen(start) - 1] = '\0';
					so_path = start;
				}
				break;
			}
		}

		fclose(fp);
	}

	return so_path;
}

static void* get_module_base(pid_t pid, const char* module_name) {
	FILE* fp;
	long addr = 0;
	char* pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				//分解字符串为一组字符串。line为要分解的字符串，"-"为分隔符字符串。  
				pch = strtok(line, "-");
				if(pch) {
					//将参数pch字符串根据参数base(表示进制)来转换成无符号的长整型数 
					addr = strtoull(pch, NULL, 16);
					break;
				}
			}
		}
		fclose(fp);
	}

	return (void*)addr;
}

static std::set<std::string> get_all_so_paths(pid_t pid) {
    char line[1024] = { 0 };
    std::set<std::string> so_paths;
    char filename[32] = { 0 };

    if (pid < 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    FILE* fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, ".so")) {
                char* start = strstr(line, "/");
                if (start) {
                    char* end = strchr(start, '\n');
                    if (end) {
                        *end = '\0';
                        so_paths.insert(std::string(start));
                    }
                }
            }
        }
        fclose(fp);
    }

    return so_paths;
}

static std::string get_app_directory(const char* package_name) {
	if(!package_name || strlen(package_name) == 0) { return {}; }
 	char line[4096] = { 0 };
    char filename[1024] = { 0 };
    snprintf(filename, sizeof(filename), "pm path %s", package_name);
	FILE * fp = popen(filename, "r");
    if (fp) {
        fread(line, 1, sizeof(line), fp);
        pclose(fp);
    }
	std::string app_path = line;
	auto start = app_path.find("/");
	if(start != std::string::npos) {
		app_path = app_path.substr(start);
	}
	auto end = app_path.find_last_of("/");
	if(end != std::string::npos) {
		app_path = app_path.substr(0, end);
	}
    return app_path;
}
}
#endif /* _KERNEL_ROOT_KIT_MAPS_HELPER_H_ */
