#ifndef ARM_ASM_HELPER_H_
#define ARM_ASM_HELPER_H_
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>


std::string AsmToBytes(const std::string& strArm64Asm) {
// 获取汇编文本

// 获取自身运行目录
char szFileName[1024] = { 0 };
readlink("/proc/self/exe", szFileName, sizeof(szFileName)-1);
std::string strMyPath = szFileName;
strMyPath = strMyPath.substr(0, strMyPath.find_last_of('/') + 1);

// 写出 input.s 文件
std::ofstream inputFile;
inputFile.open(strMyPath + "input.s", std::ios_base::out | std::ios_base::trunc);
inputFile << ".arch armv8-a\n";
inputFile << ".text\n";
inputFile << ".global _start\n";
inputFile << "_start:\n";
inputFile << strArm64Asm;
inputFile.close();

// ARM64
std::system(std::string("rm -f " + strMyPath + "output.txt").c_str());

std::string cmd = "aarch64-linux-gnu-as -o " + strMyPath + "output.o " + strMyPath + "input.s";
std::system(cmd.c_str());

cmd = "aarch64-linux-gnu-objcopy -O binary " + strMyPath + "output.o " + strMyPath + "output.bin";
std::system(cmd.c_str());

// 读取 output.bin 文件
std::ifstream in(strMyPath + "output.bin", std::ios::binary);
std::stringstream ssOutput;
if (in) // 有该文件  
{
    char buffer[1024] = {0};
    while (in.read(buffer, sizeof(buffer)))
    {
        ssOutput << std::hex;
        for(int i = 0; i < sizeof(buffer); i++) {
            ssOutput << ((buffer[i] >> 4) & 0xf) << (buffer[i] & 0xf);
        }
    }

    if (in.gcount() > 0) {
        ssOutput << std::hex;
        for(int i = 0; i < in.gcount(); i++) {
            ssOutput << ((buffer[i] >> 4) & 0xf) << (buffer[i] & 0xf);
        }
    }
    in.close();
}
std::system(std::string("rm -f " + strMyPath + "input.s").c_str());
std::system(std::string("rm -f " + strMyPath + "output.o").c_str());
std::system(std::string("rm -f " + strMyPath + "output.bin").c_str());

return ssOutput.str();
}



const char HEX[16] = {
'0', '1', '2', '3',
'4', '5', '6', '7',
'8', '9', 'a', 'b',
'c', 'd', 'e', 'f'
};

/* Convert byte array to hex string. */
std::string bytesToHexString(const std::byte* input, size_t length) {

    std::string str;
    str.reserve(length << 1);
    for (size_t i = 0; i < length; ++i) {
        int t = static_cast<int>(input[i]);
        int a = t / 16;
        int b = t % 16;
        str.append(1, HEX[a]);
        str.append(1, HEX[b]);
    }
    return str;
}

#endif /* ARM_ASM_HELPER_H_ */
