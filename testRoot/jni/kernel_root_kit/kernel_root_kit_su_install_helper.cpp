#include "kernel_root_kit_su_install_helper.h"
#include "kernel_root_kit_command.h"
#include "kernel_root_kit_init64_process_helper.h"
#include "kernel_root_kit_su_exec_data.h"
#include "kernel_root_kit_log.h"
#include "../su/su_hide_path_utils.h"
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
namespace kernel_root {
/*
 * xattr name for SELinux attributes.
 * This may have been exported via Kernel uapi header.
 */
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif
const char* selinux_file_flag = "u:object_r:system_file:s0";


bool set_file_allow_access_mode(const char* file_full_path) {
	std::string str_path = file_full_path;
	if (chmod(str_path.c_str(), 0777)) {
		ROOT_PRINTF("chmod error.\n");
		return false;
	}
	if (setxattr(str_path.c_str(), XATTR_NAME_SELINUX, selinux_file_flag, strlen(selinux_file_flag) + 1, 0)) {
		ROOT_PRINTF("setxattr error.\n");
		return false;
	}
	return true;
}

bool write_su_exec(const char* target_path) {
    std::string str_target_path = target_path;

    std::ofstream file(str_target_path, std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        ROOT_PRINTF("Could not open file %s.\n", str_target_path.c_str());
        return false;
    }
    file.write(reinterpret_cast<char*>(su_exec_data), su_exec_file_size);
    file.close();
    return true;
}



std::string install_su(const char* str_root_key, const char* base_path, ssize_t& err, const char* su_hide_folder_head_flag) {
	if (kernel_root::get_root(str_root_key) != 0) {
		err = -501;
		return {};
	}

	std::string _su_hide_folder_head_flag = su_hide_folder_head_flag;
	_su_hide_folder_head_flag += "_";

	//1.获取su_xxx隐藏目录
	std::string _su_hide_folder_path = kernel_root::su::find_su_hide_folder_path(base_path, _su_hide_folder_head_flag.c_str()); //没有再看看子目录
	if (_su_hide_folder_path.empty()) {
		//2.取不到，那就创建一个
		_su_hide_folder_path = kernel_root::su::create_su_hide_folder(str_root_key, base_path, _su_hide_folder_head_flag.c_str());
	}
	if (_su_hide_folder_path.empty()) {
		ROOT_PRINTF("su hide folder path empty error.\n");
		err = -502;
		return {};
	}
	if (!set_file_allow_access_mode(_su_hide_folder_path.c_str())) {
		ROOT_PRINTF("set file allow access mode error.\n");
		err = -503;
		return {};
	}
	std::string su_hide_full_path = _su_hide_folder_path + "/" + "su";
	if(!std::filesystem::exists(su_hide_full_path.c_str())) {
		if (!write_su_exec(su_hide_full_path.c_str())) {
			ROOT_PRINTF("copy file error.\n");
			err = -504;
			return {};
		}
		if (!set_file_allow_access_mode(su_hide_full_path.c_str())) {
			ROOT_PRINTF("set file allow access mode error.\n");
			err = -505;
			return {};
		}
	}
	err = 0;
	return su_hide_full_path;
}

std::string safe_install_su(const char* str_root_key, const char* base_path, ssize_t& err, const char* su_hide_folder_head_flag) {
	std::string su_hide_full_path;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t err;
		su_hide_full_path = install_su(str_root_key, base_path, err, su_hide_folder_head_flag);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, su_hide_full_path);
		_exit(0);
		return 0;
	}
	err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -511;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -512;
		} else if(!read_string_from_child(finfo, su_hide_full_path)) {
			err = -513;
		}
	}
	return su_hide_full_path;
}



ssize_t uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag) {

	if (kernel_root::get_root(str_root_key) != 0) {
		return -521;
	}

	std::string _su_hide_folder_head_flag = su_hide_folder_head_flag;
	_su_hide_folder_head_flag += "_";

	do {
		//获取su_xxx隐藏目录
		std::string _su_hide_path = kernel_root::su::find_su_hide_folder_path(base_path, _su_hide_folder_head_flag.c_str()); //没有再看看子目录
		if (_su_hide_path.empty()) {
			break;
		}
		//取到了，再删
		remove(std::string(_su_hide_path + std::string("/su")).c_str());

		//文件夹也删掉
		try {
			std::filesystem::remove_all(_su_hide_path);
		} catch (...) {}
		return std::filesystem::exists(_su_hide_path.c_str()) ? -512 : 0;

	} while (1);
	return 0;
}

ssize_t safe_uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag) {

	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = uninstall_su(str_root_key, base_path, su_hide_folder_head_flag);
		write_errcode_from_child(finfo, ret);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -531;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -532;
		}
	}
	return err;
}
}



