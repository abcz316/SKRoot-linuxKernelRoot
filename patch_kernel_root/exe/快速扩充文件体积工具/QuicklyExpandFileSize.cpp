// QuicklyExpandFileSize.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
#include <sstream>
using namespace std;
#define TARGET_BYTES 192*1024*1024 //目标体积大小
int main(int argc, char *argv[]) {
	char *inimage = argv[0];
	++argv;
	--argc;

	cout << "本工具用于快速扩大boot.img的文件体积" << endl << endl;


	const char *lpszFilePath = argv[0];
	FILE * pFile = fopen(lpszFilePath, "rb+");
	if (!pFile) {
		cout << "打开文件失败:" << lpszFilePath << endl;
		system("pause");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	auto nSize = ftell(pFile);
	rewind(pFile);
	if (nSize >= TARGET_BYTES) {
		cout << "目标文件体积已经大于" << TARGET_BYTES / 1024 / 1024 << "MB，无需再扩大" << endl;
		system("pause");
		return 0;
	}

	fseek(pFile, 0, SEEK_END);
	auto writeSize = TARGET_BYTES - nSize;
	void * pEmptySize = malloc(writeSize);
	if (!pEmptySize) {
		cout << "申请内存大小" << writeSize << "字节，失败" << endl;
		system("pause");
		return 0;
	}
	fwrite((char*)pEmptySize, writeSize, 1, pFile);
	free(pEmptySize);
	fclose(pFile);
	cout << "目标文件体积扩充完毕：" << TARGET_BYTES / 1024 / 1024 << "MB" << endl;
	system("pause");
	return 0;
}
