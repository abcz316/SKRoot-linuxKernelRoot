#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include "urlEncodeUtils.h"

static std::string urlDecodeToStr(std::string str) {
    std::vector<uint8_t> buf(str.length() + 1);
    url_decode(const_cast<char*>(str.c_str()), (char*)buf.data());
    return (char*)buf.data();
}
