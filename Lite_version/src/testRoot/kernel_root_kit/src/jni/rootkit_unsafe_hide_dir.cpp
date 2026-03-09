#include <string.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>

#include "rootkit_umbrella.h"
#include "rootkit_path.h"
#include "common/file_utils.h"

#define DELETE_DIR_FLAG_FILE "su"

using namespace file_utils;
namespace fs = std::filesystem;

namespace kernel_root {
KRootErr unsafe_create_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(get_root(str_root_key));

	std::string dir_path = get_hide_dir_path(str_root_key);
    // Check and create directories
    if (!create_directory_if_not_exists(dir_path.c_str())) return KRootErr::ERR_CREATE_SU_HIDE_FOLDER;
    if (!set_file_selinux_access_mode(dir_path.c_str(), SelinuxFileFlag::SELINUX_SYSTEM_FILE)) return KRootErr::ERR_SET_FILE_SELINUX;

    return KRootErr::OK;
}

KRootErr unsafe_del_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(get_root(str_root_key));
	std::string dir_path = get_hide_dir_path(str_root_key);
	return delete_path(dir_path) ? KRootErr::OK : KRootErr::ERR_DEL_SU_HIDE_FOLDER;
}

KRootErr unsafe_clean_older_hide_dir(const char* root_key) {
    RETURN_ON_ERROR(get_root(root_key));
    fs::path hide_dir_path = get_hide_dir_path(root_key);
    std::string hide_name = get_hide_dir_name(root_key);

    fs::path base_dir_path = "/data";
    DIR* dir = opendir(base_dir_path.c_str());
    if (!dir) return KRootErr::ERR_OPEN_DIR;

    std::vector<fs::path> dirs_to_delete;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) continue;
        if (entry->d_type != DT_DIR) continue;
        if (strlen(name) < hide_name.length()) continue;

        fs::path candidate_dir = base_dir_path / name;
        fs::path candidate_flag1 = candidate_dir / DELETE_DIR_FLAG_FILE;
        if (!file_exists(candidate_flag1.string())) continue;
        
        fs::path sibling_hide_dir_path = candidate_dir;
        if (hide_dir_path.lexically_normal() == sibling_hide_dir_path.lexically_normal()) continue;

        dirs_to_delete.emplace_back(std::move(candidate_dir));
    }
    closedir(dir);

    for (const auto& dir_path : dirs_to_delete) {
        delete_path(dir_path.string());
    }
    return KRootErr::OK;
}

}



