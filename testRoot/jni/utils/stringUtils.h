#ifndef STRING_UTILS_H_
#define STRING_UTILS_H_
#include <iostream>
#include <string>

static void replaceAllOccurrences(std::string& str, const std::string& toSearch, const std::string& replaceWith) {
    size_t pos = str.find(toSearch);
    while(pos != std::string::npos) {
        str.replace(pos, toSearch.length(), replaceWith);
        pos = str.find(toSearch, pos + replaceWith.length());
    }
}
#endif