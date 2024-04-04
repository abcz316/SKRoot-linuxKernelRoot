#ifndef JSON_ENCODE_UTILS_H_
#define JSON_ENCODE_UTILS_H_
#include <vector>
#include <tuple>
#include <string_view>
#include "cJSON.h"

static std::string CreateJsonBody(const std::vector<std::tuple<std::string, std::string>>& keyValuePairs) {
    cJSON *root = cJSON_CreateObject();
    if(!root) {
        return {};
    }
    for (const auto& pair : keyValuePairs) {
        cJSON_AddItemToObject(root, std::get<0>(pair).c_str(), cJSON_CreateString(std::get<1>(pair).c_str()));
    }

    char *json = cJSON_Print(root);
    std::string jsonStr(json);
    free(json);
    cJSON_Delete(root);
    return jsonStr;
}

static std::string GetMiddleJsonString(std::string_view text) {
    std::string jsonString;
    int jsonStart = text.find("{");
	int jsonEnd = text.find_last_of("}");
	if(jsonStart != std::string::npos && jsonEnd != std::string::npos) {
        jsonString = text.substr(jsonStart, jsonEnd - jsonStart + 1);
	}
    return jsonString;
}

#endif