#include "rootkit_su_install.h"

#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>

#include "su/su_inline.h"
#include "rootkit_umbrella.h"
#include "rootkit_path.h"
#include "rootkit_fork_helper.h"
#include "rootkit_unsafe_hide_dir.h"
#include "common/file_replace_string.h"
#include "common/file_utils.h"

using namespace file_utils;
namespace kernel_root {

#ifdef SU_DATA
static bool write_su_exec(const char* str_root_key, const char* target_path) {
	std::shared_ptr<char> sp_su_file_data(new (std::nothrow) char[su_file_size], std::default_delete<char[]>());
	if(!sp_su_file_data) {
		return false;
	}
	memcpy(sp_su_file_data.get(), reinterpret_cast<char*>(su_data), su_file_size);

	// write root key
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_su_rootkey), sizeof(static_inline_su_rootkey), str_root_key, sp_su_file_data.get(), su_file_size)) {
		return false;
	}

    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return false;
    }
    file.write(sp_su_file_data.get(), su_file_size);
    file.close();
    return true;
}

static KRootErr unsafe_install_su(const char* str_root_key, std::string& out_su_full_path) {
	RETURN_ON_ERROR(get_root(str_root_key));
	RETURN_ON_ERROR(unsafe_clean_older_hide_dir(str_root_key));
	RETURN_ON_ERROR(unsafe_create_su_hide_dir(str_root_key));

	std::string su_full_path = get_su_hide_path(str_root_key);
	if (!write_su_exec(str_root_key, su_full_path.c_str())) return KRootErr::ERR_WRITE_SU_EXEC;
	if (!set_file_selinux_access_mode(su_full_path.c_str(), SelinuxFileFlag::SELINUX_SYSTEM_FILE)) return KRootErr::ERR_SET_FILE_SELINUX;
	
	out_su_full_path = su_full_path;
	return KRootErr::OK;
}

static KRootErr safe_install_su(const char* str_root_key, std::string& out_su_full_path) {
	out_su_full_path.clear();
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr err = unsafe_install_su(str_root_key, out_su_full_path);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, out_su_full_path);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	else if(!read_string_from_child(finfo, out_su_full_path)) err = KRootErr::ERR_READ_CHILD_STRING;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr install_su_with_cb(const char* str_root_key, void (*cb)(const char* su_full_path)) {
	std::string su_path;
	RETURN_ON_ERROR(safe_install_su(str_root_key, su_path));
	cb(su_path.c_str());
	return KRootErr::OK;
}
#endif



static KRootErr unsafe_uninstall_su(const char* str_root_key) {
	RETURN_ON_ERROR(get_root(str_root_key));
	RETURN_ON_ERROR(unsafe_clean_older_hide_dir(str_root_key));
	RETURN_ON_ERROR(unsafe_del_su_hide_dir(str_root_key));
	return KRootErr::OK;
}

static KRootErr safe_uninstall_su(const char* str_root_key) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr err = unsafe_uninstall_su(str_root_key);
		write_errcode_from_child(finfo, err);
		finfo.close_all();
		_exit(0);
		return KRootErr::OK;
	}
	KRootErr err = KRootErr::OK;
	if(!read_errcode_from_child(finfo, err)) err = KRootErr::ERR_READ_CHILD_ERRCODE;
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr uninstall_su(const char* str_root_key) {
	return safe_uninstall_su(str_root_key);
}

}



