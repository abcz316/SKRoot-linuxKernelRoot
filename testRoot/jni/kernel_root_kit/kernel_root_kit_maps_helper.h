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

static std::string find_app_directory_by_maps(const std::set<std::string>& all_so_paths, const char* package_name) {
	for (const auto& full_path : all_so_paths) {
		if(full_path.empty()) {
			continue;
		}
		if(full_path.substr(0,1) != "/") {
			continue;
		}
		if(full_path.find(package_name) == std::string::npos) {
			continue;
		}

		// 从所给的路径开始，逐层向上查找，直到找到 package_name 或到达顶级目录为止
		std::filesystem::path path(full_path);
		std::string app_path;
		for (const auto& component : path) {
			app_path += component;
			if(component.string().find(package_name) != std::string::npos) {
				break;
			}
			app_path += component == "/" ? "" : "/";
		}
		return app_path;
	}
    return {};
}
}
#endif /* _KERNEL_ROOT_KIT_MAPS_HELPER_H_ */
