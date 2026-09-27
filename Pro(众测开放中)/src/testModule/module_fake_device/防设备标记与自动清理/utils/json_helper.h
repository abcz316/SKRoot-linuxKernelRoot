#pragma once
#include <iostream>
#include <map>
#include <utility>
#include <vector>
#include "third_party/cJSON.h"

std::string convert_2_json_app_list(const std::vector<std::pair<std::string, std::string>> & appList) {
    std::string strJson;
    cJSON *json = cJSON_CreateObject();
    if(json) {
        cJSON *jsonArray = cJSON_CreateArray();
        for(const auto & app: appList) {
            cJSON *jsonApp = cJSON_CreateObject();
            cJSON_AddStringToObject(jsonApp, "packageName", app.first.c_str());
            cJSON_AddStringToObject(jsonApp, "labelBase64", app.second.c_str());
            cJSON_AddItemToArray(jsonArray, jsonApp);
        }
        cJSON_AddItemToObject(json, "content", jsonArray);

        char *jsonString = cJSON_Print(json);
        if(jsonString) {
            strJson = jsonString;
            free(jsonString);
        }
        cJSON_Delete(json);
    }
    return strJson;
}
