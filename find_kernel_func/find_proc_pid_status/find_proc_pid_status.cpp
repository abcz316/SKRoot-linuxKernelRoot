#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include "../3rdparty/find_xrefs.h"
#pragma comment(lib, "../3rdparty/capstone-4.0.2-win64/capstone.lib")

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

	char feature_text_tracerpid[] = {
		'\n', 'T', 'r', 'a', 'c', 'e', 'r', 'P', 'i', 'd', ':', '\t', '\0',
	};
	char feature_text_seccomp[] = {
		'\n', 'S', 'e', 'c', 'c', 'o', 'm', 'p', ':', '\t', '\0',
	};
	size_t tracerpid_text_offset = 0;
	size_t seccomp_text_offset = 0;

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if ((image_size - offset) >= sizeof(feature_text_tracerpid)) {
			if (tracerpid_text_offset == 0 && memcmp(paddr, &feature_text_tracerpid, sizeof(feature_text_tracerpid)) == 0) {
				printf("TracerPid text->0x%p\n", (void*)offset);
				tracerpid_text_offset = offset;
			}
		}
		if ((image_size - offset) >= sizeof(feature_text_seccomp)) {
			if (seccomp_text_offset == 0 && memcmp(paddr, &feature_text_seccomp, sizeof(feature_text_seccomp)) == 0) {
				printf("Seccomp text->0x%p\n", (void*)offset);
				seccomp_text_offset = offset;
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
}

int main(int argc, char* argv[]) {
	char* inimage = argv[0];
	++argv;
	--argc;

	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}

	int nFileSize = 0;

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
