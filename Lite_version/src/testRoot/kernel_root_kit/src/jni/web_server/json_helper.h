#pragma once
#include <iostream>
#include <map>
#include <vector>
#include "cJSON.h"

std::string convert_2_json(const std::string & str, const std::map<std::string, std::string> & appendParam = {}) {
    std::string strJson;
    cJSON *json = cJSON_CreateObject();
    if(json) {
        cJSON_AddStringToObject(json, "content", str.c_str());
        for(const auto & param: appendParam) cJSON_AddStringToObject(json, param.first.c_str(), param.second.c_str());
        char *jsonString = cJSON_Print(json);
        if(jsonString) {
            strJson = jsonString;
            free(jsonString);
        }
        cJSON_Delete(json);
    }
    return strJson;
}

std::string convert_2_json_m(const std::string & str, const std::map<std::string, std::string> & appendParam = {}) {
    std::string strJson;
    cJSON *json = cJSON_CreateObject();
    if(json) {
        cJSON_AddStringToObject(json, "content", str.c_str());
        cJSON *jsonArray = cJSON_CreateArray();
        for(const auto & param: appendParam) {
            cJSON *jsonMap = cJSON_CreateObject();
            cJSON_AddStringToObject(jsonMap, param.first.c_str(), param.second.c_str());
            cJSON_AddItemToArray(jsonArray, jsonMap);
        }
        cJSON_AddItemToObject(json, "arr_map", jsonArray);
        char *jsonString = cJSON_Print(json);
        if(jsonString) {
            strJson = jsonString;
            free(jsonString);
        }
        cJSON_Delete(json);
    }
    return strJson;
}

std::string convert_2_json_v(const std::vector<std::string> &v, const std::map<std::string, std::string> & appendParam = {}) {
    std::string strJson;
    cJSON *json = cJSON_CreateObject();
    if (json) {
        cJSON *jsonArray = cJSON_CreateArray();
        for (const std::string &str : v) cJSON_AddItemToArray(jsonArray, cJSON_CreateString(str.c_str()));
        cJSON_AddItemToObject(json, "content", jsonArray);
        for(const auto & param: appendParam) cJSON_AddStringToObject(json, param.first.c_str(), param.second.c_str());
        char *jsonString = cJSON_Print(json);
        if (jsonString) {
            strJson = jsonString;
            free(jsonString);
        }
        cJSON_Delete(json);
    }
    return strJson;
}

std::string get_json_str(const std::string& json, const char* key) {
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return {};
    cJSON* j_str = cJSON_GetObjectItem(root, key);
    std::string result = j_str ? j_str->valuestring : "";
    cJSON_Delete(root); 
    return result;
}

int get_json_int(const std::string& json, const char* key) {
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return {};
    cJSON* j_int = cJSON_GetObjectItem(root, key);
    int n = j_int ? j_int->valueint : 0;
    cJSON_Delete(root); 
    return n;
}
