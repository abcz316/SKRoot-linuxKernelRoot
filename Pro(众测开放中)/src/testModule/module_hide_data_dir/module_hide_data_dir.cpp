#include <sys/stat.h>
#include <cerrno>
#include <map>
#include <set>
#include <fstream>
#include <thread>
#include "patch_filldir64.h"
#include "patch_compat_filldir.h"
#include "patch_mtk_hbt_filldir64.h"
#include "patch_iterate_dir.h"
#include "kernel_module_kit_umbrella.h"
#include "hide_dir_json_utils.h"
#include "simple_hash_util.h"

namespace fs = std::filesystem;

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

// 把path集合解析成ino集合：stat获取；stat失败的path回退用备用json里存的历史ino兜底
static std::set<uint64_t> collect_ino_set(const std::set<std::string>& paths) {
    std::set<uint64_t> ino_set;
    const std::map<std::string, uint64_t> backup_ino_map = hide_dir_json::load_ino_backup();
    for (const auto& path : paths) {
        uint64_t ino = 0;
        if(!get_path_inode(path.c_str(), ino)) {
            const auto it = backup_ino_map.find(path);
            if (it != backup_ino_map.end() && it->second != 0) {
                printf("stat failed, use backup ino: %s -> %llu\n", path.c_str(), (unsigned long long)it->second);
                ino_set.insert(it->second);
            }
            continue;
        }
        ino_set.insert(ino);
    }
    return ino_set;
}

static KModErr patch_mtk_hbt_filldir64(const PatchBase& patchBase, const std::set<std::string>& names, const std::set<uint64_t>& ino_set, uint64_t original_hbt_filldir64, uint64_t iterate_dir) {
    KModErr err = KModErr::OK;
    PatchMtkHbtFilldir64 patchMtkHbtFilldir64(patchBase, original_hbt_filldir64);
    PatchIterateDir patchIterateDir(patchBase, iterate_dir);

    uint64_t fake_hbt_filldir64 = 0;
    RETURN_IF_ERROR(patchMtkHbtFilldir64.generate_hook_fake_filldir64(names, ino_set, fake_hbt_filldir64));
    
    err = patchIterateDir.patch_iterate_dir(original_hbt_filldir64, fake_hbt_filldir64);
    printf("patch iterate_dir: %s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    return err;
}

// 开始修补内核
static KModErr patch_kernel_handler(const HideDirConfig& config, const std::string& whitelist_comm_name) {
    kernel_module::SymbolHit filldir64;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("filldir64", filldir64, kernel_module::SymbolMatchMode::Prefix));
    printf("%s, addr: %p\n", filldir64.name, (void*)filldir64.addr);
    
    kernel_module::SymbolHit compat_filldir;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("compat_filldir", compat_filldir, kernel_module::SymbolMatchMode::Prefix));
    printf("%s, addr: %p\n", compat_filldir.name, (void*)compat_filldir.addr);

    uint64_t mtk_hbt_filldir64 = 0;
    kernel_module::kallsyms_lookup_name("hbt:filldir64", mtk_hbt_filldir64);
    printf("hbt_filldir64, addr: %p\n", (void*)mtk_hbt_filldir64);
   
	uint64_t iterate_dir = 0;
    kernel_module::kallsyms_lookup_name("iterate_dir", iterate_dir);
    printf("iterate_dir, addr: %p\n", (void*)iterate_dir);

    uint32_t cred_offset = 0;
    uint32_t cred_euid_offset = 0;
    uint32_t comm_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_cred_offset(cred_offset));
    printf("cred offset: 0x%x\n", cred_offset);
    RETURN_IF_ERROR(kernel_module::get_cred_euid_offset(cred_euid_offset));
    printf("cred euid offset: 0x%x\n", cred_euid_offset);
    RETURN_IF_ERROR(kernel_module::get_task_struct_comm_offset(comm_offset));
    printf("comm offset: 0x%x\n", comm_offset);

    const std::set<uint64_t> ino_set = collect_ino_set(config.paths);
    if(config.names.empty() && ino_set.empty()) {
        printf("no names and ino_set, skip\n");
        return KModErr::OK;
    }

    PatchBase patchBase(cred_offset, cred_euid_offset, comm_offset, whitelist_comm_name);
    PatchFilldir64 patchFilldir64(patchBase, filldir64.addr);
    PatchCompatFilldir patchCompatFilldir(patchBase, compat_filldir.addr);
    KModErr err = patchFilldir64.patch_filldir64(config.names, ino_set);
    printf("patch filldir64 ret: %s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    err = patchCompatFilldir.patch_compat_filldir(config.names, ino_set);
    printf("patch compat_filldir ret: %s\n", to_string(err).c_str());
    RETURN_IF_ERROR(err);
    if(mtk_hbt_filldir64 && iterate_dir) {
        RETURN_IF_ERROR(patch_mtk_hbt_filldir64(patchBase, config.names, ino_set, mtk_hbt_filldir64, iterate_dir));
    }
    return err;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    HideDirConfig config = hide_dir_json::load_config();
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
        if(path == "/getHiddenDirsJson") hide_dir_json::read_config_json(resp);
        else if(path == "/setHiddenDirsJson") resp = handle_set_hidden_dirs_json(body);
        else if(path == "/checkFileExist") resp = handle_check_file_exist(body);
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }

private:
    std::string handle_set_hidden_dirs_json(const std::string& body) {
        HideDirConfig config = hide_dir_json::parse_config(body);
        // 收集path对应的ino，一次性写入备用json（下次启动stat失败时兜底）
        std::map<std::string, uint64_t> ino_map;
        for (const auto& path : config.paths) {
            uint64_t ino = 0;
            if(!get_path_inode(path.c_str(), ino)) continue;
            if(ino == 0) continue;
            ino_map[path] = ino;
        }
        if (!hide_dir_json::save_ino_backup(ino_map)) printf("write ino backup json failed\n");
        return hide_dir_json::save_config_json(body) ? "OK" : "FAILED";
    }

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
SKROOT_MODULE_VERSION("2.0.6")
SKROOT_MODULE_DESC("内核级隐藏 /data 指定目录，彻底阻断文件扫描；底层拦截机制，免疫各类基于漏洞的暴力扫盘。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("ae12076c010ebabbb233affdd0239c14")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_data_dir/update.json")