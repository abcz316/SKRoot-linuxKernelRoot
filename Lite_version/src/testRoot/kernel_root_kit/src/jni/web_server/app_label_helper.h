#pragma once

#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include "cJSON.h"
#include "rootkit_umbrella.h"

namespace app_label_helper {
inline bool parse_json(const std::string & json, std::map<std::string, std::string> & result) {
    if (json.empty()) return false;
    size_t begin = json.find('[');
    size_t end = json.rfind(']');
    if (begin == std::string::npos || end == std::string::npos || end <= begin) return false;

    std::string json_array = json.substr(begin, end - begin + 1);
    cJSON * root = cJSON_Parse(json_array.c_str());
    if (!root) return false;
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return false;
    }

    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON * item = cJSON_GetArrayItem(root, i);
        if (!item) continue;
        cJSON * j_package_name = cJSON_GetObjectItem(item, "packageName");
        cJSON * j_label_base64 = cJSON_GetObjectItem(item, "labelBase64");
        if (!j_package_name || !j_package_name->valuestring) continue;
        // 不解析 base64，原值填入
        result[j_package_name->valuestring] = (j_label_base64 && j_label_base64->valuestring) ? j_label_base64->valuestring : "";
    }
    cJSON_Delete(root);
    return true;
}

inline std::map<std::string, std::string> get_all_app_display_names(const char* root_key, const char* work_dir, const void* dex_data, size_t dex_size) {
    static std::map<std::string, std::string> s_cache;
    if (!s_cache.empty()) return s_cache;

	if (!root_key || !work_dir || !dex_data || dex_size == 0) return {};

    std::string app_label_helper_path = work_dir;
    app_label_helper_path += "/app_label_helper.dex";

    remove(app_label_helper_path.c_str());
    std::ofstream file(app_label_helper_path, std::ios::binary | std::ios::out);
    if (!file.is_open()) return {};

    file.write(reinterpret_cast<const char*>(dex_data), dex_size);
    bool write_ok = file.good();
    file.close();
    if (!write_ok) return {};

    if (chmod(app_label_helper_path.c_str(), 0644)) return {};

    std::stringstream cmd;
    cmd << "CLASSPATH=" << app_label_helper_path << " app_process /system/bin AppLabelsHelper";

    std::string json;
    KRootErr err = kernel_root::run_root_cmd(root_key, cmd.str().c_str(), json);
    remove(app_label_helper_path.c_str());
    if (is_failed(err)) return {};

    std::map<std::string, std::string> result;
    parse_json(json, result);
	
    bool all_ok = result.size() > 5;
    for (const auto & kv : result) {
        if (kv.first.empty() || kv.second.empty()) {
            all_ok = false;
            break;
        }
    }
    if (all_ok) s_cache = result;
    return result;
}

} // namespace app_label_helper
