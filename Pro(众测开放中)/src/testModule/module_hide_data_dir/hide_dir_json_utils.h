#pragma once
#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include "cJSON.h"
#include "module_base_disk_storage.h"
#include "module_err_def.h"

// 隐藏规则配置（隐藏规则json反序列化的结果）
struct HideDirConfig {
    // 按目录名称隐藏
    std::set<std::string> names;
    // 按完整路径隐藏
    std::set<std::string> paths;
    bool empty() const { return names.empty() && paths.empty(); }
    size_t size() const { return names.size() + paths.size(); }
};

namespace hide_dir_json {

// 磁盘持久化存储key
static constexpr const char* CONFIG_KEY     = "hide_dir_json";      // 隐藏规则json
static constexpr const char* INO_BACKUP_KEY = "hide_dir_ino_json";  // path->ino 备用表json

/***************************************************************************
 * 隐藏规则json，格式：
 * [
 *   {"type":"name","value":"local123"},
 *   {"type":"path","value":"/data/aaa/bbb"}
 * ]
 ***************************************************************************/
static HideDirConfig parse_config(const std::string& json) {
    HideDirConfig result;
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return result;
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return result;
    }
    const int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; ++i) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(item)) continue;
        cJSON* type_item = cJSON_GetObjectItemCaseSensitive(item, "type");
        cJSON* value_item = cJSON_GetObjectItemCaseSensitive(item, "value");
        if (!cJSON_IsString(type_item) || !type_item->valuestring) continue;
        if (!cJSON_IsString(value_item) || !value_item->valuestring) continue;
        const std::string type = type_item->valuestring;
        const std::string value = value_item->valuestring;
        if (value.empty()) continue;
        if (type == "name") {
            result.names.insert(value);
        } else if (type == "path") {
            result.paths.insert(value);
        } else {
            printf("unknown hide rule type: %s\n", type.c_str());
        }
    }
    cJSON_Delete(root);
    return result;
}

static HideDirConfig load_config() {
    std::string json;
    kernel_module::read_string_disk_storage(CONFIG_KEY, json);
    return parse_config(json);
}

static bool read_config_json(std::string& out) {
    return is_ok(kernel_module::read_string_disk_storage(CONFIG_KEY, out));
}

static bool save_config_json(const std::string& json) {
    return is_ok(kernel_module::write_string_disk_storage(CONFIG_KEY, json.c_str()));
}

/***************************************************************************
 * path -> ino 备用表json，格式：
 * [
 *   {"path":"/data/aaa/bbb","ino":123456}
 * ]
 ***************************************************************************/
static std::map<std::string, uint64_t> parse_ino_map(const std::string& json) {
    std::map<std::string, uint64_t> result;
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return result;
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return result;
    }
    const int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; ++i) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(item)) continue;
        cJSON* path_item = cJSON_GetObjectItemCaseSensitive(item, "path");
        cJSON* ino_item = cJSON_GetObjectItemCaseSensitive(item, "ino");
        if (!cJSON_IsString(path_item) || !path_item->valuestring || path_item->valuestring[0] == '\0') continue;
        if (!cJSON_IsNumber(ino_item)) continue;
        const uint64_t ino = static_cast<uint64_t>(ino_item->valuedouble);
        if (ino == 0) continue;
        result[path_item->valuestring] = ino;
    }
    cJSON_Delete(root);
    return result;
}

static std::map<std::string, uint64_t> load_ino_backup() {
    std::string json;
    kernel_module::read_string_disk_storage(INO_BACKUP_KEY, json);
    return parse_ino_map(json);
}

static bool save_ino_backup(const std::map<std::string, uint64_t>& ino_map) {
    cJSON* root = cJSON_CreateArray();
    if (!root) return false;
    for (const auto& entry : ino_map) {
        cJSON* item = cJSON_CreateObject();
        if (!item) continue;
        cJSON_AddStringToObject(item, "path", entry.first.c_str());
        cJSON_AddNumberToObject(item, "ino", static_cast<double>(entry.second));
        cJSON_AddItemToArray(root, item);
    }
    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return false;
    const bool ok = is_ok(kernel_module::write_string_disk_storage(INO_BACKUP_KEY, json));
    cJSON_free(json);
    return ok;
}

}
