#include "module_hide_data_dir.h"
#include "patch_filldir64.h"
#include "cJSON.h"
#include <set>

#include "kernel_module_kit_umbrella.h"

#define MOD_VER "1.0.4"

// 把 ["aa","bb","cc"] 解析成 std::set<std::string>
static std::set<std::string> parse_json(const std::string& json) {
    std::set<std::string> result;
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
        result.insert(std::string(item->valuestring));
    }
    cJSON_Delete(root);
    return result;
}

// 开始修补内核
static KModErr patch_kernel_handler(const std::set<std::string>& hide_dir_list) {
    kernel_module::SymbolHit filldir64;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("filldir64", kernel_module::SymbolMatchMode::Prefix, filldir64));
    printf("%s, addr: %p\n", filldir64.name, (void*)filldir64.addr);

    PatchBase patchBase;
    PatchFilldir64 patchFilldir64(patchBase, filldir64.addr);
    KModErr err = patchFilldir64.patch_filldir64(hide_dir_list);
    printf("patch filldir64 ret: %s\n", to_string(err).c_str());
    return err;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("Hello! module_hide_data_dir!\n");

    //读取配置文件内容
    std::string json;
    kernel_module::read_string_disk_storage("hide_dir_json", json);
    std::set<std::string> hide_dir_list = parse_json(json);
    if(hide_dir_list.empty()) {
        printf("hide dir list is empty.\n");
        return 0;
    }
    printf("hide dir list (%zd total) :\n", hide_dir_list.size());
    for (const auto& item : hide_dir_list) printf("hide dir: %s\n", item.c_str());

    KModErr err = patch_kernel_handler(hide_dir_list);
    printf("patch_kernel_handler ret:%s\n", to_string(err).c_str());
    return 0;
}


// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        m_root_key = root_key;
    }

    // 这里的Web服务器仅起到读取、保存配置文件的作用。
    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        printf("[module_hide_data_dir] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getVersion") resp = MOD_VER;
        else if(path == "/getHiddenDirsJson") kernel_module::read_string_disk_storage("hide_dir_json", resp);
        else if(path == "/setHiddenDirsJson") resp = is_ok(kernel_module::write_string_disk_storage("hide_dir_json", body.c_str())) ? "OK" : "FAILED";
            
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
private:
    std::string m_root_key;
};

// SKRoot 模块名片
SKROOT_MODULE_NAME("隐藏/data目录")
SKROOT_MODULE_VERSION(MOD_VER)
SKROOT_MODULE_DESC("内核级隐藏 /data 指定目录，彻底阻断文件扫描；底层拦截机制，免疫各类基于漏洞的暴力扫盘。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_UUID32("ae12076c010ebabbb233affdd0239c14")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_data_dir/update.json")