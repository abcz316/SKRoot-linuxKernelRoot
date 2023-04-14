#include <stdio.h>
#include <iostream>
#include <malloc.h>
#include <windows.h>
#include <vector>
#include "../3rdparty/find_xrefs.h"
#pragma comment(lib, "../3rdparty/capstone-4.0.2-win64/capstone.lib")


struct partInfo {
	size_t pos = 0;
	char partHex[160 * 4] = { 0 };
	BOOL bIsTBZCmdUpMiddle = FALSE;
	BOOL bIsMovFFFFFFF5CmdUpMiddle = FALSE;

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

	return buffer;
}

const char* FindBytes(const char* pWaitSearchAddress, size_t nLen, const char* bForSearch, size_t ifLen) {
	for (size_t i = 0; i < nLen; i++) {
		char* pData = (char*)(pWaitSearchAddress + i);
		char* bTemForSearch = (char*)bForSearch;
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

static inline size_t abs_sub(size_t a1, size_t a2) {
	size_t b1 = a1 > a2 ? a1 : a2;
	size_t b2 = a1 > a2 ? a2 : a1;
	return b1 - b2;
}

void RemoveDuplicatePartInfo(std::vector<partInfo>& vPartInfo) {
	std::vector<partInfo> vResult;
	for (const partInfo& part : vPartInfo) {
		bool bShow = false;
		for (const partInfo& item : vResult) {
			if (item.pos == part.pos) {
				bShow = true;
				break;
			}
		}
		if (!bShow) {
			vResult.push_back(part);
		}
	}
	vPartInfo.clear();
	for (const partInfo& part : vResult) {
		vPartInfo.push_back(part);
	}
}

void RemoveDuplicateFuncStartResultMap(std::map<size_t, std::shared_ptr<size_t>>& resultMap) {
	std::map<size_t, std::shared_ptr<size_t>> newResultMap;
	for (auto iter1 = resultMap.begin(); iter1 != resultMap.end(); iter1++) {
		bool exist = false;
		if (iter1->second && *iter1->second) {
			for (auto iter2 = newResultMap.begin(); iter2 != newResultMap.end(); iter2++) {
				if (iter2->second && *iter2->second == *iter1->second) {
					exist = true;
					break;
				}
			}
		}
		if (exist) {
			continue;
		}
		newResultMap[iter1->first] = iter1->second;
	}
	resultMap = newResultMap;
}


void SearchFeature1(char* image, int size) {

	char feature1[1 * 4] = {
		'\x3F','\xFC','\x3F','\xB1',
	};

	std::vector<partInfo> vSearch;
	for (int i = 0; i < 32; i++) {
		char* pAddress = (char*)FindBytes(image, size, &feature1[i * 4], 4);
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
			pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature1[i * 4], 4);
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

	std::vector<partInfo> vSearch5;
	for (int i = 0; i < vSearch2.size(); i++) {
		partInfo info = vSearch2.at(i);
		for (int y = 0; y < 31; y++) {
			for (size_t s3 = 0; s3 < sizeof(info.partHex); s3 += 4) {
				if (memcmp((void*)((size_t)info.partHex + (size_t)s3), (BYTE*)&feature2[y * 4], 4) == 0) {
					if (s3 < sizeof(info.partHex) / 2) {
						//MOV W?, #0xFFFFFFF5命令在上面的
						info.bIsMovFFFFFFF5CmdUpMiddle = TRUE;
					}
#ifdef _DEBUG
					printf("Debug:0x%llx, MOV W%d, #0xFFFFFFF5, TBZorTBNZ up middle:【%d】, MOV W?, #0xFFFFFFF5 up middle:【%d】\n",
						info.pos, y, info.bIsTBZCmdUpMiddle, info.bIsMovFFFFFFF5CmdUpMiddle);
#endif
					vSearch5.push_back(info);
				}
			}
		}
	}
	RemoveDuplicatePartInfo(vSearch5);
	std::map<size_t, std::shared_ptr<size_t>> result_map;
	for (size_t i = 0; i < vSearch5.size(); i++) {
		result_map[vSearch5[i].pos] = std::make_shared<size_t>();
	}
	find_func_haed_link(image, size, result_map);
	RemoveDuplicateFuncStartResultMap(result_map);
	printf_head_result_map(result_map);
}

void SearchFeature2(const char* image, size_t image_size) {
	char feature_text_dev[13] = {
	0x2F, 0x64, 0x65, 0x76, 0x2F, 0x66, 0x64, 0x2F, 0x25, 0x64, 0x2F, 0x25, 0x73
	};
	char feature_text_runasinitprocess[26] = {
	0x01, 0x36, 0x52, 0x75, 0x6E, 0x20, 0x25, 0x73, 0x20, 0x61, 0x73, 0x20, 0x69, 0x6E, 0x69, 0x74,
	0x20, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x0A, 0x00
	};
	char feature_text_sbininit[] = {
	"/sbin/init"
	};
	size_t dev_text_offset = 0;
	size_t runasinitprocess_text_offset = 0;
	size_t sbininit_text_offset = 0;

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if (dev_text_offset == 0 && (image_size - offset) >= sizeof(feature_text_dev)) {
			if (memcmp(paddr, &feature_text_dev, sizeof(feature_text_dev)) == 0) {
				printf("dev text->0x%llx\n", (void*)offset);
				dev_text_offset = offset;
			}
		}
		if (runasinitprocess_text_offset == 0 && (image_size - offset) >= sizeof(feature_text_runasinitprocess)) {
			if (memcmp(paddr, &feature_text_runasinitprocess, sizeof(feature_text_runasinitprocess)) == 0) {
				printf("runasinitprocess text->0x%llx\n", (void*)offset);
				runasinitprocess_text_offset = offset;
			}
		}
		if (sbininit_text_offset == 0 && (image_size - offset) >= sizeof(feature_text_sbininit)) {
			if (memcmp(paddr, &feature_text_sbininit, sizeof(feature_text_sbininit)) == 0) {
				printf("sbininit text->0x%llx\n", (void*)offset);
				sbininit_text_offset = offset;
			}
		}
	}

	printf("\n");

	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>> result_map;
	result_map[{"[do_execve]", dev_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	result_map[{"[run_init_process]", runasinitprocess_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	result_map[{"[kernel_init]", sbininit_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	for (auto iter = result_map.begin(); iter != result_map.end();) {
		if (std::get<1>(iter->first) == 0) {
			iter = result_map.erase(iter);
		} else {
			iter++;
		}
	}
	if (result_map.size() == 0) {
		printf("[ERROR] text offset empty.\n");
		return;
	}
	find_xrefs_link((const char*)image, image_size, result_map);
	printf_xrefs_result_map(result_map);
	
	auto sp_vec_rip = result_map[{"[run_init_process]", runasinitprocess_text_offset}];
	auto sp_vec_ki = result_map[{"[kernel_init]", sbininit_text_offset}];
	if (sp_vec_rip && sp_vec_ki && sp_vec_rip->size() && sp_vec_ki->size()) {
		if (abs_sub(sp_vec_rip->at(0).xrefs_location, sp_vec_ki->at(0).xrefs_location) <= 4*8) {
			std::cout << "请注意！当前[run_init_process]已被内联进[kernel_init]，即在[kernel_init]里能找到[do_execve]" << std::endl;
			std::cout << "提示：当[run_init_process]与[kernel_init]的搜索结果表明是同一片的代码执行位置时，意味着[run_init_process]已被内联进[kernel_init]" << std::endl;
		}
	}
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
