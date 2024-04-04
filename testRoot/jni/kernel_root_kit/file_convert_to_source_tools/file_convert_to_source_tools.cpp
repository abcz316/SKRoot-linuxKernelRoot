// file_convert_to_source_tools.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

void OutputSourceFile(const std::string& sourceCode, int nFileSize, int nBuffValCount) {
    std::ofstream file("res.h");
    if (!file) {
        std::cerr << "无法打开输出文件 res.h\n";
        return;
    }

    file << "namespace {\n";
    file << "static int fileSize = " << nFileSize << ";\n";
    file << "static uint64_t data[" << nBuffValCount << "] = {\n";
    file << sourceCode << "\n";
    file << "};\n";
    file << "}\n";
}

void processFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "打开文件失败: " << filePath << "\n";
        return;
    }

    std::streamsize nFileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(nFileSize);
    if (!file.read(buffer.data(), nFileSize)) {
        std::cerr << "读取文件失败: " << filePath << "\n";
        return;
    }

    int yu = nFileSize % 8;
    if (yu > 0) {
        yu = 8 - yu;
    }
    buffer.resize(nFileSize + yu, 0); // 扩大并填充零

    std::ostringstream code;
    for (int i = 0; i < buffer.size() / 8; i++) {
        uint64_t val = *(uint64_t*)&buffer[i * 8];
        if (i > 0) {
            code << ", ";
            if (i % 3 == 0) {
                code << "\n";
            }
        }
        code << "0x" << std::hex << val;
    }

    OutputSourceFile(code.str(), nFileSize, buffer.size() / 8);
    std::cout << "完成\n";
}

int main(int argc, char* argv[]) {
#ifdef _DEBUG
    const char* filePath = R"***(D:\123.txt)***";
#else
    if (argc < 2) {
        std::cerr << "无输入文件\n";
        return 1;
    }
    const char* filePath = argv[1];
#endif

    processFile(filePath);
    std::cin.get();
    return 0;
}
