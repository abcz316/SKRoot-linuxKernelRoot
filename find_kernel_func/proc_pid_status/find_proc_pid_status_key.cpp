// find_proc_pid_status_key.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <vector>
#include <sstream>

char* GetFileBuf(const char* lpszFilePath, int& nSize) {
	/* 若要一个byte不漏地读入整个文件，只能采用二进制方式打开 */
	FILE* pFile = fopen(lpszFilePath, "rb");
	if (!pFile) {
		return NULL;
	}

	/* 获取文件大小 */
	fseek(pFile, 0, SEEK_END);
	nSize = ftell(pFile);
	rewind(pFile);

	/* 分配内存存储整个文件 */
	char* buffer = (char*)malloc(sizeof(char) * nSize);
	if (!buffer) {
		return NULL;
	}

	/* 将文件拷贝到buffer中 */
	size_t result = fread(buffer, 1, nSize, pFile);
	if ((int)result != nSize) {
		free(buffer);
		return NULL;
	}
	/* 现在整个文件已经在buffer中，可由标准输出打印内容 */

	/* 结束演示，关闭文件并释放内存 */
	fclose(pFile);
	// free(buffer);
	return buffer;
}

char feature_text_tracerpid[] = {
	'\n', 'T', 'r', 'a', 'c', 'e', 'r', 'P', 'i', 'd', ':', '\t', '\0',
};
char feature_text_seccomp[] = {
	'\n', 'S', 'e', 'c', 'c', 'o', 'm', 'p', ':', '\t', '\0',
};

void SearchFeature(const char* image, size_t size) {
	for (size_t offset = 0; offset < size; offset++) {
		if ((size - offset) < sizeof(feature_text_tracerpid)) {
			break;
		}
		const char* paddr = image + offset;
		if (memcmp(paddr, &feature_text_tracerpid, sizeof(feature_text_tracerpid)) == 0) {
			printf("TracerPid text 0x%p\n", (void*)offset);
			break;
		}
	}
	for (size_t offset = 0; offset < size; offset++) {
		if ((size - offset) < sizeof(feature_text_seccomp)) {
			break;
		}
		const char* paddr = image + offset;
		if (memcmp(paddr, &feature_text_seccomp, sizeof(feature_text_seccomp)) == 0) {
			printf("Seccomp text 0x%p\n", (void*)offset);
			break;
		}
	}
	std::cout << "以上文本特征位置已为你准备好，请使用IDA先跳转至以上位置，然后使用IDA自带的【交叉引用】功能进行再次跳转，可直达proc_pid_status位置" << std::endl << std::endl;
	std::cout << "请注意proc_pid_status里面的Uid取值是real_cred而不是cred，需将real_cred的值+8才能得到cred，即cred=real_cred+8" << std::endl << std::endl;
}

int main(int argc, char* argv[]) {
	char* inimage = argv[0];
	++argv;
	--argc;

	std::cout << "本工具用于查找在Linux内核文件中proc_pid_status的文本特征位置，注意：暂不支持2G以上文件大小" << std::endl;

#ifdef _DEBUG
#else
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}
#endif

	int nFileSize = 0;

#ifdef _DEBUG
	char* image = GetFileBuf(R"***(D:\Android.Image.Kitchen.v3.8-Win32\split_img\269.img-kernel)***", nFileSize);
#else
	char* image = GetFileBuf(argv[0], nFileSize);
#endif
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
