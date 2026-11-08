#pragma once
#include <cstdio>
#include <vector>
#include <string>
#include "cJSON.h"

// 把 ["aa","bb","cc"] 解析成 std::vector<std::string>
inline std::vector<std::string> parse_json(const std::string& json) {
    std::vector<std::string> result;
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return result;
    if (root->type != cJSON_Array) {
        cJSON_Delete(root);
        return result;
    }
    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; ++i) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (!item) continue;
        if (item->type != cJSON_String) continue;
        if (!item->valuestring) continue;
        result.push_back(std::string(item->valuestring));
    }
    cJSON_Delete(root);
    return result;
}

// 把 set<string> 导出为 JSON 数组字符串：["aa","bb","cc"]
inline std::string json_array_from_set(const std::vector<std::string>& s) {
    cJSON* arr = cJSON_CreateArray();
    for (const auto& k : s) {
        cJSON* str = cJSON_CreateString(k.c_str());
        cJSON_AddItemToArray(arr, str);
    }
    char* out = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!out) return "[]";
    std::string ret(out);
    cJSON_free(out);
    return ret;
}

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}
