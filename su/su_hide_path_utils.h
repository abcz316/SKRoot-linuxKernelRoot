#ifndef _SU_HIDDEN_FOLDER_PATH_UTILS_H_
#define _SU_HIDDEN_FOLDER_PATH_UTILS_H_
#include <unistd.h>
#include <dirent.h>
#include <stdarg.h>
#include <string.h>
#include <sstream>
#include <sys/stat.h>
#include <time.h>
#include "base64.h"
#include "log.h"
#include "../testRoot/random_utils.h"

#define RANDOM_GUID_LEN 10
#define ROOT_KEY_LEN 48

namespace {
	namespace __private {

		static inline char* substr(const char* _str, int pos, int len) {
			static char ptr[10];

			memcpy(ptr, _str + pos - 1, len);
			ptr[len] = '\0';

			return ptr;
		}

		static inline std::string encry_key(const char* src, const char* key) {
			int KeyPos = -1;
			int SrcPos = 0;
			int SrcAsc = 0;
			time_t t;

			int KeyLen = strlen(key);
			if (KeyLen == 0)
				return "";

			srand((unsigned)time(&t));
			int offset = rand() % 255;

			char buff[3];
			sprintf(buff, "%1.2x", offset);

			//sprintf(buff, "%1.2x", offset);
			std::string dest = buff;

			for (int i = 0; i < strlen(src); i++) {
				SrcAsc = (src[i] + offset) % 255;

				if (KeyPos < KeyLen - 1)
					KeyPos++;
				else
					KeyPos = 0;

				SrcAsc = SrcAsc ^ key[KeyPos];

				memset(buff, 0, sizeof(buff));
				sprintf(buff, "%1.2x", SrcAsc);
				//sprintf(buff, "%1.2x", SrcAsc);   
				dest = dest + (std::string)buff;

				offset = SrcAsc;
			}
			return dest;
		}
		static inline std::string uncry_key(const char* src, const char* key) {
			int KeyLen = strlen(key);
			if (KeyLen == 0)
				return "";

			int KeyPos = -1;
			int offset = 0;
			std::string dest = "";
			int SrcPos = 0;
			int SrcAsc = 0;
			int TmpSrcAsc = 0;

			char buff[5];
			sprintf(buff, "0x%s", substr(src, 1, 2));
			sscanf(buff, "%x", &offset);
			SrcPos = 3;
			while (SrcPos <= strlen(src)) {
				sprintf(buff, "0x%s", substr(src, SrcPos, 2));
				sscanf(buff, "%x", &SrcAsc);
				if (KeyPos < KeyLen - 1)
					KeyPos++;
				else
					KeyPos = 0;

				TmpSrcAsc = SrcAsc ^ key[KeyPos];

				if (TmpSrcAsc <= offset)
					TmpSrcAsc = 255 + TmpSrcAsc - offset;
				else
					TmpSrcAsc = TmpSrcAsc - offset;

				dest += char(TmpSrcAsc);
				offset = SrcAsc;
				SrcPos = SrcPos + 2;
			}

			return dest;
		}
	}
}

static std::string find_su_hide_folder_path(const char* base_path, const char* su_hide_folder_head_flag = "su") {
	std::string id;
	DIR* dir;
	struct dirent * entry;
	const char* su_head = su_hide_folder_head_flag;

	dir = opendir(base_path);
	if (dir == NULL)
		return id;

	while ((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strlen(entry->d_name) <= strlen(su_head)) {
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

static std::string create_su_hide_folder(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag) {

	char guid[RANDOM_GUID_LEN] = { 0 };
	rand_str(guid, sizeof(guid));
	std::string encodeRootKey(guid, sizeof(guid));
	encodeRootKey += str_root_key;

	encodeRootKey = base64_encode((const unsigned char*)encodeRootKey.c_str(), encodeRootKey.length());

	//密匙保留仅仅当天有效
	time_t CurTime = time(NULL);
	std::string encryKey = std::to_string(localtime(&CurTime)->tm_mday * RANDOM_GUID_LEN);
	encodeRootKey = __private::encry_key((const char*)encodeRootKey.c_str(), encryKey.c_str());

	std::string file_path = base_path;
	file_path += "/";
	file_path += su_hide_folder_head_flag;
	file_path += encodeRootKey;
	file_path += "/";
	if (mkdir(file_path.c_str(), 0755)) {
		TRACE("create_su_hide_folder error:%s\n", file_path.c_str());
		return {};
	}
	if (chmod(file_path.c_str(), 0777)) {
		TRACE("chmod error:%s\n", file_path.c_str());
		return {};
	}
	return file_path;
}

static inline std::string parse_root_key_by_myself_path(const char* myself_path) {
	std::string path = myself_path;
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


	//密匙保留仅仅当天有效
	time_t CurTime = time(NULL);
	std::string encryKey = std::to_string(localtime(&CurTime)->tm_mday * RANDOM_GUID_LEN);
	std::string  decodeRootKey = __private::uncry_key((const char*)path.c_str(), encryKey.c_str());

	decodeRootKey = base64_decode(decodeRootKey);


	if (decodeRootKey.length() < (RANDOM_GUID_LEN + ROOT_KEY_LEN)) {
		return {};
	}
	return decodeRootKey.substr(decodeRootKey.length() - ROOT_KEY_LEN);
}

#endif /* _SU_HIDDEN_FOLDER_PATH_UTILS_H_ */
