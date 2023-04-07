#include <stdio.h>
#include <iostream>
#include <malloc.h>
#include <windows.h>
#include <vector>
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
	
	return buffer;
}

char* FindBytes(char* pWaitSearchAddress, size_t nLen, char* bForSearch, size_t ifLen) {
	for (size_t i = 0; i < nLen; i++) {
		char* pData = (char*)(pWaitSearchAddress + i);
		char* bTemForSearch = bForSearch;
		bool bContinue = false;
		for (size_t y = 0; y < ifLen; y++, ++pData, ++bTemForSearch) {
			if (*pData != *bTemForSearch) {
				bContinue = true;
				break;
			}
		}
		if (bContinue) {
			continue;
		}
		return pWaitSearchAddress + i;
	}
	return 0;
}

struct partInfo {
	DWORD pos = 0;
	char partHex[160 * 4] = { 0 }; 
	BOOL bIsTBZCmdUpMiddle = FALSE; 
	BOOL bIsMovFFFFFFF5CmdUpMiddle = FALSE; 
};
void SearchFeature1(char* image, int size) {

	char feature1[1 * 4] = {
		'\x3F','\xFC','\x3F','\xB1',
	};

	std::vector<partInfo> vSearch;
	for (int i = 0; i < 32; i++) {
		char* pAddress = FindBytes(image, size, &feature1[i * 4], 4);
		while (pAddress) {

			partInfo info;
			if ((size - (size_t)pAddress - (size_t)image) < sizeof(info.partHex) / 2) {
				break;
			} else if ((pAddress - image) < sizeof(info.partHex) / 2) {
				break;
			}
			info.pos = (size_t)pAddress - (size_t)image;
			size_t targetAddr = (size_t)pAddress - sizeof(info.partHex) / 2;
			memcpy(&info.partHex, (void*)targetAddr, sizeof(info.partHex));
			vSearch.push_back(info);

			pAddress += 4;
			pAddress = FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature1[i * 4], 4);
		}
	}


	char feature4[31 * 4] = {
		'\x00','\x78','\x13','\x12',
		'\x21','\x78','\x13','\x12',
		'\x42','\x78','\x13','\x12',
		'\x63','\x78','\x13','\x12',
		'\x84','\x78','\x13','\x12',
		'\xA5','\x78','\x13','\x12',
		'\xC6','\x78','\x13','\x12',
		'\xE7','\x78','\x13','\x12',
		'\x08','\x79','\x13','\x12',
		'\x29','\x79','\x13','\x12',
		'\x4A','\x79','\x13','\x12',
		'\x6B','\x79','\x13','\x12',
		'\x8C','\x79','\x13','\x12',
		'\xAD','\x79','\x13','\x12',
		'\xCE','\x79','\x13','\x12',
		'\xEF','\x79','\x13','\x12',
		'\x10','\x7A','\x13','\x12',
		'\x31','\x7A','\x13','\x12',
		'\x52','\x7A','\x13','\x12',
		'\x73','\x7A','\x13','\x12',
		'\x94','\x7A','\x13','\x12',
		'\xB5','\x7A','\x13','\x12',
		'\xD6','\x7A','\x13','\x12',
		'\xF7','\x7A','\x13','\x12',
		'\x18','\x7B','\x13','\x12',
		'\x39','\x7B','\x13','\x12',
		'\x5A','\x7B','\x13','\x12',
		'\x7B','\x7B','\x13','\x12',
		'\x9C','\x7B','\x13','\x12',
		'\xBD','\x7B','\x13','\x12',
		'\xDE','\x7B','\x13','\x12',
	};
	std::vector<partInfo> vSearch4;
	for (int i = 0; i < vSearch.size(); i++) {
		for (int y = 0; y < sizeof(feature4) / 4; y++) {
			partInfo info = vSearch.at(i);
			for (size_t s = 0; s < sizeof(info.partHex); s += 4) {
				if (memcmp((void*)((size_t)info.partHex + (size_t)s), (BYTE*)&feature4[y * 4], 4) == 0) {
					vSearch4.push_back(info);
					break;
				}
			}
		}
	}

	std::vector<partInfo> vSearch2;
	for (int i = 0; i < vSearch4.size(); i++) {
		partInfo info = vSearch4.at(i);
		for (size_t s2 = 0; s2 < sizeof(info.partHex); s2 += 4) {
			BYTE ch1 = '\x36';
			BYTE ch2 = '\x37';
			auto memCh = *(BYTE*)((size_t)info.partHex + s2 + 3);
			if (memCh == ch1 || memCh == ch2) {
				if (s2 < sizeof(info.partHex) / 2) {
					
					info.bIsTBZCmdUpMiddle = TRUE;
				}
				vSearch2.push_back(info);
				break;
			}
		}
	}

































	char feature2[31 * 4] = {
'\x40','\x01','\x80','\x12',
'\x41','\x01','\x80','\x12',
'\x42','\x01','\x80','\x12',
'\x43','\x01','\x80','\x12',
'\x44','\x01','\x80','\x12',
'\x45','\x01','\x80','\x12',
'\x46','\x01','\x80','\x12',
'\x47','\x01','\x80','\x12',
'\x48','\x01','\x80','\x12',
'\x49','\x01','\x80','\x12',
'\x4A','\x01','\x80','\x12',
'\x4B','\x01','\x80','\x12',
'\x4C','\x01','\x80','\x12',
'\x4D','\x01','\x80','\x12',
'\x4E','\x01','\x80','\x12',
'\x4F','\x01','\x80','\x12',
'\x50','\x01','\x80','\x12',
'\x51','\x01','\x80','\x12',
'\x52','\x01','\x80','\x12',
'\x53','\x01','\x80','\x12',
'\x54','\x01','\x80','\x12',
'\x55','\x01','\x80','\x12',
'\x56','\x01','\x80','\x12',
'\x57','\x01','\x80','\x12',
'\x58','\x01','\x80','\x12',
'\x59','\x01','\x80','\x12',
'\x5A','\x01','\x80','\x12',
'\x5B','\x01','\x80','\x12',
'\x5C','\x01','\x80','\x12',
'\x5D','\x01','\x80','\x12',
'\x5E','\x01','\x80','\x12',
	};

	std::vector<size_t> vShowFinished;
	for (int i = 0; i < vSearch2.size(); i++) {
		partInfo info = vSearch2.at(i);
		for (int y = 0; y < 31; y++) {
			for (size_t s3 = 0; s3 < sizeof(info.partHex); s3 += 4) {
				if (memcmp((void*)((size_t)info.partHex + (size_t)s3), (BYTE*)&feature2[y * 4], 4) == 0) {
					if (s3 < sizeof(info.partHex) / 2) {
						
						info.bIsMovFFFFFFF5CmdUpMiddle = TRUE;
					}

					
					bool bShow = false;
					for (size_t showFinishedAddr : vShowFinished) {
						if (showFinishedAddr == info.pos) {
							bShow = true;
							break;
						}
					}

					if (!bShow) {
						
						decltype(info.pos) funcStartAddr = 0;
						for (SSIZE_T start = sizeof(info.partHex) / 2; start >= 0; start -= 4) {
							
							char featureRet[1 * 4] = {
							'\xC0','\x03','\x5F','\xD6'
							};
							if (memcmp((void*)((size_t)info.partHex + (size_t)start), (BYTE*)&featureRet[0 * 4], 4) == 0) {
								SSIZE_T offset = start - sizeof(info.partHex) / 2 + 4;
								funcStartAddr = info.pos + offset;
								break;
							}
						}
						printf("0x%p\n",funcStartAddr);
						
						vShowFinished.push_back(info.pos);
					}

					break;
				}
			}
		}
	}
}

void SearchFeature2(const char* image, size_t image_size) {
	char feature_text_dev[13] = {
	0x2F, 0x64, 0x65, 0x76, 0x2F, 0x66, 0x64, 0x2F, 0x25, 0x64, 0x2F, 0x25, 0x73
	};
	size_t dev_text_offset = 0;

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if ((image_size - offset) >= sizeof(feature_text_dev)) {
			if (dev_text_offset == 0 && memcmp(paddr, &feature_text_dev, sizeof(feature_text_dev)) == 0) {
				printf("dev fd text->0x%p\n", (void*)offset);
				dev_text_offset = offset;
				break;
			}
		}
	}
	if (!dev_text_offset) {
		printf("[ERROR] text offset empty.\n");
		return;
	}
	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>> result_map;
	result_map[{"do_execve function", dev_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
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
	std::cout << "===============Engine1===============" << std::endl;
	SearchFeature1(image, nFileSize);
	std::cout << "===============Engine2===============" << std::endl;
	SearchFeature2(image, nFileSize);
	free(image);
	system("pause");
	return 0;

}
