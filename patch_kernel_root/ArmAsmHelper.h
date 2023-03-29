#ifndef ARM_ASM_HELPER_H_
#define ARM_ASM_HELPER_H_
#include <string>
#include <windows.h>
#include <fstream>
#include <sstream>

std::string AsmToBytes(const std::string& strArm64Asm) {
	//获取汇编文本

	//获取自身运行目录
	char szFileName[MAX_PATH] = { 0 };
	::GetModuleFileNameA(NULL, szFileName, MAX_PATH);
	std::string strMyPath = szFileName;
	strMyPath = strMyPath.substr(0, strMyPath.find_last_of('\\') + 1);

	//写出input.txt
	std::ofstream inputFile;
	inputFile.open(strMyPath + "input.txt", std::ios_base::out | std::ios_base::trunc);
	inputFile << strArm64Asm;
	inputFile.close();

	//ARM64
	DeleteFileA(std::string(strMyPath + "output.txt").c_str());

	std::string cmd = strMyPath + "aarch64-linux-android-as.exe -ahlm " + strMyPath + "input.txt >> " + strMyPath + "output.txt";
	system(cmd.c_str());

	//未开发的
	//ARM：arm-linux-as.exe -ahlm -k -mthumb-interwork -march=armv7-a %s >> %s
	//Thumb：arm-linux-as.exe -ahlm -k -mthumb-interwork -march=armv7 %s >> %s

	//读取output.txt
	std::ifstream in(strMyPath + "output.txt");
	std::stringstream ssOutput;
	std::string line;
	bool bIsFirstLine = true;
	if (in) // 有该文件  
	{
		while (getline(in, line)) // line中不包括每行的换行符  
		{
			if (bIsFirstLine) {
				bIsFirstLine = false;
				continue;
			}
			if (!line.length()) { continue; }
			if (line.length() == 1 && line == "\n") { continue; }
			if (line.find("AARCH64 GAS") != -1) { continue; }

			std::stringstream ssGetMidBuf;
			std::string word;
			ssGetMidBuf << line;
			int n = 0;
			while (ssGetMidBuf >> word) {
				n++;
				if (n == 3) {
					ssOutput << word;
				}
				word.empty();
			}


		}
		in.close();
	}

	return ssOutput.str();

}

const char HEX[16] = {
'0', '1', '2', '3',
'4', '5', '6', '7',
'8', '9', 'a', 'b',
'c', 'd', 'e', 'f'
};

/* Convert byte array to hex string. */
std::string bytesToHexString(const byte* input, size_t length) {

	std::string str;
	str.reserve(length << 1);
	for (size_t i = 0; i < length; ++i) {
		int t = input[i];
		int a = t / 16;
		int b = t % 16;
		str.append(1, HEX[a]);
		str.append(1, HEX[b]);
	}
	return str;
}

#endif /* ARM_ASM_HELPER_H_ */
