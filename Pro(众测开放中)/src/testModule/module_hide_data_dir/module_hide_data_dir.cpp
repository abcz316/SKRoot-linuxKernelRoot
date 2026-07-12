#include <set>

#include "patch_filldir64.h"
#include "kernel_module_kit_umbrella.h"
#include "simple_hash_util.h"
#include "cJSON.h"

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
static KModErr patch_kernel_handler(const std::set<std::string>& hide_dir_list, const std::string& whitelist_comm_name) {
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

    PatchBase patchBase(cred_offset, cred_euid_offset, comm_offset, whitelist_comm_name);
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
    printf("hide dir list (%zd total) :\n", hide_dir_list.size());
    if(hide_dir_list.empty()) return 0;
    
    for (const auto& item : hide_dir_list) printf("hide dir: %s\n", item.c_str());

    KModErr err = patch_kernel_handler(hide_dir_list, SimpleHashUtil::to_random_string(root_key).data());
    printf("patch_kernel_handler ret:%s\n", to_string(err).c_str());
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
            
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("隐藏/data目录")
SKROOT_MODULE_VERSION("1.0.8")
SKROOT_MODULE_DESC("内核级隐藏 /data 指定目录，彻底阻断文件扫描；底层拦截机制，免疫各类基于漏洞的暴力扫盘。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("ae12076c010ebabbb233affdd0239c14")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_data_dir/update.json")