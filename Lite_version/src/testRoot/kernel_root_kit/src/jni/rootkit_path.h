#pragma once
#include <iostream>
#include <filesystem>
#include "rootkit_umbrella.h"

#ifndef FOLDER_HEAD_ROOT_KEY_LEN
#define FOLDER_HEAD_ROOT_KEY_LEN 16
#endif

#define DIR_FMT "/data/%s/"

namespace kernel_root {
	
static std::string get_hide_dir_name(const char* root_key) {
	return std::string(root_key).substr(0, FOLDER_HEAD_ROOT_KEY_LEN);
}

static std::string get_hide_dir_path(const char* root_key) {
    char hide_dir[1024] = {0};
	snprintf(hide_dir, sizeof(hide_dir), DIR_FMT, get_hide_dir_name(root_key).c_str());
	return hide_dir;
}


static std::string get_su_hide_path(const char* root_key) {
	return (std::filesystem::path(get_hide_dir_path(root_key)) / "su").string();
}
}