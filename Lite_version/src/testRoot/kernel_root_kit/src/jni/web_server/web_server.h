#pragma once

#include <string>
#include <cstdio>

static void writeToLog(const std::string & message) {
    printf("%s\n", message.c_str());
    // std::ofstream logFile("/sdcard/web_server.log", std::ios::app);
    // if (!logFile) {
    //     std::cerr << "Error opening file" << std::endl;
    //     return;
    // }
    // logFile << message << std::endl;
    // logFile.close();
    // std::cout << message << std::endl;
}