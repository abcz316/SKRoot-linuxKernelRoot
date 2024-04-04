#ifndef _SU_HIDDEN_FOLDER_PATH_UTILS_H_
#define _SU_HIDDEN_FOLDER_PATH_UTILS_H_
#include <dirent.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../utils/base64.h"
#include "encryptor.h"

#define RANDOM_GUID_LEN 8
#define ROOT_KEY_LEN 48
#define ENCRYKEY "ECC08B04-B9FF-40B5-9596-4408626181D5"

namespace kernel_root{
namespace su{

static std::string find_su_hide_folder_path(
	const char* base_path,
	const char* su_hide_folder_head_flag = "su") {
	std::string id;
	DIR* dir;
	struct dirent* entry;
	const char* su_head = su_hide_folder_head_flag;

	dir = opendir(base_path);
	if (dir == NULL)
		return id;

	while ((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") == 0) ||
			(strcmp(entry->d_name, "..") == 0)) {
			continue;
		} else if (entry->d_type != DT_DIR) {
			continue;
		} else if (strlen(entry->d_name) <= strlen(su_head)) {
			continue;
		}
		if (!strstr(entry->d_name, su_head)) {
			continue;
		}
		id = base_path;
		id += "/";
		id += entry->d_name;
		break;
	}
	closedir(dir);
	return id;
}

static std::string create_su_hide_folder(const char* str_root_key,
										 const char* base_path,
										 const char* su_hide_folder_head_flag) {
	char guid[RANDOM_GUID_LEN] = {0};
	rand_str(guid, sizeof(guid));
	std::string encodeRootKey(guid, sizeof(guid));
	encodeRootKey += str_root_key;

	encodeRootKey = base64_encode((const unsigned char*)encodeRootKey.c_str(),
								  encodeRootKey.length());
	encodeRootKey = encryp_string(encodeRootKey, ENCRYKEY);

	std::string file_path = base_path;
	file_path += "/";
	file_path += su_hide_folder_head_flag;
	file_path += encodeRootKey;
	file_path += "/";
	if (mkdir(file_path.c_str(), 0755)) {
		return {};
	}
	if (chmod(file_path.c_str(), 0777)) {
		return {};
	}
	return file_path;
}

static inline std::string parse_root_key_by_su_path(
	const char* su_path) {
	std::string path = su_path;
	if (path.empty()) {
		return {};
	}
	int n = path.find_last_of("_");
	if (n == -1) {
		return {};
	}
	path = path.substr(++n);
	n = path.find("/");
	if (n != -1) {
		path.substr(0, n);
	}

	std::string decodeRootKey = uncryp_string(path, ENCRYKEY);

	decodeRootKey = base64_decode(decodeRootKey);

	if (decodeRootKey.length() < (RANDOM_GUID_LEN + ROOT_KEY_LEN)) {
		return {};
	}
	return decodeRootKey.substr(decodeRootKey.length() - ROOT_KEY_LEN);
}
}
}
#endif /* _SU_HIDDEN_FOLDER_PATH_UTILS_H_ */
