#include <sys/stat.h>
#include <set>
#include <fstream>
#include "patch_filldir64.h"
#include "kernel_module_kit_umbrella.h"
#include "simple_hash_util.h"
#include "cJSON.h"

namespace fs = std::filesystem;

struct HideDirConfig {
    // 按目录名称隐藏
    std::set<std::string> names;
    // 按完整路径隐藏
    std::set<std::string> paths;
    bool empty() const { return names.empty() && paths.empty(); }
    size_t size() const { return names.size() + paths.size(); }
};

// 解析：
// [
//   {"type":"name","value":"local123"},
//   {"type":"path","value":"/data/aaa/bbb"}
// ]
static HideDirConfig parse_json(const std::string& json) {
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

static bool get_path_inode(const char* path, uint64_t& inode) {
    inode = 0;
    if (path == nullptr || path[0] == '\0') return false;
    struct stat st {};
    if (::stat(path, &st) != 0) {
        printf("stat failed: %s, errno: %d (%s)\n", path, errno, std::strerror(errno));
        return false;
    }
    inode = static_cast<uint64_t>(st.st_ino);
    return true;
}

// 开始修补内核
static KModErr patch_kernel_handler(const HideDirConfig& config, const std::string& whitelist_comm_name) {
    kernel_module::SymbolHit filldir64;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("filldir64", filldir64, kernel_module::SymbolMatchMode::Prefix));
    printf("%s, addr: %p\n", filldir64.name, (void*)filldir64.addr);
    uint32_t cred_offset = 0;
    uint32_t cred_euid_offset = 0;
    uint32_t comm_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_cred_offset(cred_offset));
    printf("cred offset: 0x%x\n", cred_offset);
    RETURN_IF_ERROR(kernel_module::get_cred_euid_offset(cred_euid_offset));
    printf("cred euid offset: 0x%x\n", cred_euid_offset);
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(comm_offset));
    printf("comm offset: 0x%x\n", comm_offset);

    std::set<uint64_t> ino_set;
    for (const auto& path : config.paths) {
        uint64_t ino = 0;
        if(!get_path_inode(path.c_str(), ino)) continue;
        ino_set.insert(ino);
    }

    PatchBase patchBase(cred_offset, cred_euid_offset, comm_offset, whitelist_comm_name);
    PatchFilldir64 patchFilldir64(patchBase, filldir64.addr);
    KModErr err = patchFilldir64.patch_filldir64(config.names, ino_set);
    printf("patch filldir64 ret: %s\n", to_string(err).c_str());
    return err;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    std::string json;
    kernel_module::read_string_disk_storage("hide_dir_json", json);
    HideDirConfig config = parse_json(json);
    printf("hide dir rules (%zu total, %zu names, %zu paths):\n", config.size(), config.names.size(), config.paths.size());
    if (config.empty()) return 0;
    for (const auto& name : config.names) {
        printf("hide name: %s\n", name.c_str());
    }
    for (const auto& path : config.paths) {
        printf("hide path: %s\n", path.c_str());
    }
    KModErr err = patch_kernel_handler(config, SimpleHashUtil::to_random_string(root_key).data());
    printf("patch_kernel_handler ret: %s\n", to_string(err).c_str());
    return is_ok(err) ? 0 : -1;
}

// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    // 这里的Web服务器仅起到读取、保存配置文件的作用。
    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        printf("[module_hide_data_dir] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getHiddenDirsJson") kernel_module::read_string_disk_storage("hide_dir_json", resp);
        else if(path == "/setHiddenDirsJson") resp = is_ok(kernel_module::write_string_disk_storage("hide_dir_json", body.c_str())) ? "OK" : "FAILED";
        else if(path == "/checkFileExist") resp = handle_check_file_exist(body);
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }

private:
    std::string handle_check_file_exist(const std::string& filepath) {
        if (filepath.empty()) return "false";
        std::error_code ec;
        const bool exists = fs::exists(filepath, ec);
        return !ec && exists ? "true" : "false";
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("隐藏/data目录")
SKROOT_MODULE_VERSION("2.0.0")
SKROOT_MODULE_DESC("内核级隐藏 /data 指定目录，彻底阻断文件扫描；底层拦截机制，免疫各类基于漏洞的暴力扫盘。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("ae12076c010ebabbb233affdd0239c14")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_data_dir/update.json")