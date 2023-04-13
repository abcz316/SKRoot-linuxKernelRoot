#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include "../3rdparty/find_xrefs.h"
#pragma comment(lib, "../3rdparty/capstone-4.0.2-win64/capstone.lib")

struct feature_info {
	std::shared_ptr<char> sp_data;
	size_t data_len;
};

char* GetFileBuf(const char* lpszFilePath, int& nSize) {
	FILE* pFile = fopen(lpszFilePath, "rb");
	if (!pFile) {
		return NULL;
	}
	fseek(pFile, 0, SEEK_END);
	nSize = ftell(pFile);
	rewind(pFile);

	char* buffer = (char*)malloc(sizeof(char) * nSize);
	if (!buffer) {
		return NULL;
	}

	size_t result = fread(buffer, 1, nSize, pFile);
	if ((int)result != nSize) {
		free(buffer);
		return NULL;
	}
	fclose(pFile);
	// free(buffer);
	return buffer;
}

void SearchFeature(const char* image, size_t image_size) {

	std::vector<feature_info> v_feature_text_tracerpid;
	std::vector<feature_info> v_feature_text_seccomp;
	{
		char feature_text_tracerpid[] = {
		'\n', 'T', 'r', 'a', 'c', 'e', 'r', 'P', 'i', 'd', ':', '\t', '\0',
		};
		std::shared_ptr<char> sp_data(new (std::nothrow) char[sizeof(feature_text_tracerpid)], std::default_delete<char[]>());
		memcpy(sp_data.get(), feature_text_tracerpid, sizeof(feature_text_tracerpid));
		v_feature_text_tracerpid.push_back({ sp_data, sizeof(feature_text_tracerpid) });
	}
	{
		char feature_text_tracerpid[] = {
		'S', 't', 'a', 't', 'e', ':', '\t', '%', 's', '\n',
		};
		std::shared_ptr<char> sp_data(new (std::nothrow) char[sizeof(feature_text_tracerpid)], std::default_delete<char[]>());
		memcpy(sp_data.get(), feature_text_tracerpid, sizeof(feature_text_tracerpid));
		v_feature_text_tracerpid.push_back({ sp_data, sizeof(feature_text_tracerpid) });
	}
	{
		char feature_text_seccomp[] = {
		'\n', 'S', 'e', 'c', 'c', 'o', 'm', 'p', ':', '\t', '\0',
		};
		std::shared_ptr<char> sp_data(new (std::nothrow) char[sizeof(feature_text_seccomp)], std::default_delete<char[]>());
		memcpy(sp_data.get(), feature_text_seccomp, sizeof(feature_text_seccomp));
		v_feature_text_seccomp.push_back({ sp_data, sizeof(feature_text_seccomp) });
	}
	{
		char feature_text_seccomp[] = {
		'S', 'e', 'c', 'c', 'o', 'm', 'p', ':', '\t', '\0',
		};
		std::shared_ptr<char> sp_data(new (std::nothrow) char[sizeof(feature_text_seccomp)], std::default_delete<char[]>());
		memcpy(sp_data.get(), feature_text_seccomp, sizeof(feature_text_seccomp));
		v_feature_text_seccomp.push_back({ sp_data, sizeof(feature_text_seccomp) });
	}
	{
		char feature_text_seccomp[] = {
		'S', 'e', 'c', 'c', 'o', 'm', 'p', ':', '\t', '%', 'd', '\n', '\0',
		};
		std::shared_ptr<char> sp_data(new (std::nothrow) char[sizeof(feature_text_seccomp)], std::default_delete<char[]>());
		memcpy(sp_data.get(), feature_text_seccomp, sizeof(feature_text_seccomp));
		v_feature_text_seccomp.push_back({ sp_data, sizeof(feature_text_seccomp) });
	}

	size_t tracerpid_text_offset = 0;
	size_t seccomp_text_offset = 0;

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if (tracerpid_text_offset == 0) {
			for (size_t i = 0; i < v_feature_text_tracerpid.size(); i++) {
				const auto& item = v_feature_text_tracerpid[i];
				if ((image_size - offset) >= item.data_len) {
					if (memcmp(paddr, item.sp_data.get(), item.data_len) == 0) {
						printf("TracerPid[%zd] text->0x%llx\n", i, (void*)offset);
						tracerpid_text_offset = offset;
						break;
					}
				}
			}
		}

		if (seccomp_text_offset == 0) {
			for (size_t i = 0; i < v_feature_text_seccomp.size(); i++) {
				const auto& item = v_feature_text_seccomp[i];
				if ((image_size - offset) >= item.data_len) {
					if (memcmp(paddr, item.sp_data.get(), item.data_len) == 0) {
						printf("Seccomp[%zd] text->0x%llx\n", i,  (void*)offset);
						seccomp_text_offset = offset;
						break;
					}
				}
			}
		}

		if (tracerpid_text_offset && seccomp_text_offset) {
			break;
		}
	}
	if (!tracerpid_text_offset || !seccomp_text_offset) {
		printf("[ERROR] text offset empty.\n");
		return;
	}
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>> result_map;
	result_map[{"proc_pid_status (cred) function", tracerpid_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	result_map[{"proc_pid_status (seccomp) function", seccomp_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	find_xrefs_link((const char*)image, image_size, result_map);
	printf_xrefs_result_map(result_map);
	std::cout << "请注意！proc_pid_status里面的Uid取值不是cred而是real_cred，需将real_cred的值+8才能得到cred，即cred=real_cred+8" << std::endl;
}

int main(int argc, char* argv[]) {
	char* inimage = argv[0];
	++argv;
	--argc;


	int nFileSize = 0;
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}
	char* image = GetFileBuf(argv[0], nFileSize);
	if (!image) {
		std::cout << "打开文件失败:" << argv[0] << std::endl;
		system("pause");
		return 0;
	}
	SearchFeature((const char*)image, nFileSize);
	free(image);
	system("pause");
	return 0;
}
