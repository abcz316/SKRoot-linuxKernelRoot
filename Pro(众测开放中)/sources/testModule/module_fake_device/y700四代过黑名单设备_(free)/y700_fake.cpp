#include <set>
#include <unordered_map>

#include "y700_fake.h"
#include "cJSON.h"
#include "android_packages_list_utils.h"
#include "persist_data_perm_helper.h"


#define SYSTEM_PROP_SH "system_prop.sh"

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

// 把 set<string> 导出为 JSON 数组字符串：["aa","bb","cc"]
static std::string json_array_from_set(const std::set<std::string>& s) {
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

// 扫描 /data/user/<uid>/ 里是否存在以 prefix 开头的包目录（例如 com.android.）
static bool has_pkg_dir_with_prefix_in_data_user(const std::string& prefix) {
    const fs::path user_root = "/data/user";
    std::error_code ec;

    if (!fs::exists(user_root, ec) || ec) return false;
    if (!fs::is_directory(user_root, ec) || ec) return false;

    // /data/user/<userId> 通常是数字目录：0, 10, 999...
    for (const auto& u : fs::directory_iterator(user_root, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!u.is_directory(ec) || ec) { ec.clear(); continue; }

        const std::string uid = u.path().filename().string();
        if (!is_all_digits(uid)) continue;

        // 扫描 /data/user/<userId>/<pkgDir>
        std::error_code ec2;
        for (const auto& pkg : fs::directory_iterator(u.path(), fs::directory_options::skip_permission_denied, ec2)) {
            if (ec2) { ec2.clear(); break; }
            if (!pkg.is_directory(ec2) || ec2) { ec2.clear(); continue; }

            const std::string name = pkg.path().filename().string();
            if (name.rfind(prefix, 0) == 0) {
                return true; // 找到 com.android.* 目录
            }
        }
    }
    return false;
}

// 阻塞等待：每 interval 检测一次，直到满足条件后执行一次 on_decrypted
static void wait_decrypted_and_run(std::function<void()> on_decrypted,
                                  std::chrono::seconds interval = std::chrono::seconds(3),
                                  const std::string& prefix = "com.android.") {
    for (;;) {
        if (has_pkg_dir_with_prefix_in_data_user(prefix)) {
            // 解密成功：只执行一次
            on_decrypted();
            return;
        }
        std::this_thread::sleep_for(interval);
    }
}

static bool remove_ano_tmp_for_pkg(const std::string& pkg) {
    if (pkg.empty()) return false;

    const fs::path user_root = "/data/user";
    std::error_code ec;
    if (!fs::exists(user_root, ec) || !fs::is_directory(user_root, ec) || ec) return false;

    bool hit_any = false;
    for (const auto& entry : fs::directory_iterator(user_root, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_directory(ec)) { ec.clear(); continue; }

        const std::string uid = entry.path().filename().string();
        if (!is_all_digits(uid)) continue;

        fs::path ano_tmp = entry.path() / pkg / "files" / "ano_tmp";
        if (fs::exists(ano_tmp, ec) && !ec && fs::is_directory(ano_tmp, ec) && !ec) {
            hit_any = true;
            fs::remove_all(ano_tmp, ec);
            printf("remove ano_tmp success: %s\n", pkg.c_str());
        }
    }
    return hit_any;
}

static void monitor_pkgs_loop(const std::set<std::string>& pkgs) {
    using namespace std::chrono_literals;
    std::unordered_map<std::string, bool> last; // pkg -> last running
    last.reserve(pkgs.size() * 2);
    bool last_any_running = false;
    for (;;) {
        bool any_running = false;
        for (const auto& pkg : pkgs) {
            bool cur = is_pkg_running(pkg);
            bool prev = last[pkg];       // 不存在时默认 false，并插入
            last[pkg] = cur;
            if (cur) any_running = true;
            // 进程“消失”就清理一次
            if (prev && !cur) remove_ano_tmp_for_pkg(pkg);
        }
        // 任意一个启动：只触发一次 lockdown
        if (!last_any_running && any_running) persist_data_on_install_lockdown_permissions();

        // 最后一个关闭：只触发一次 restore
        if (last_any_running && !any_running) persist_data_on_uninstall_restore_permissions();

        last_any_running = any_running;
        std::this_thread::sleep_for(5s);
    }
}

static void daemon_loop() {
    std::string json;
    kernel_module::read_string_disk_storage("target_pkg_json", json);
    std::set<std::string> target_pkg_list = parse_json(json);
    printf("target pkg list (%zd total) :\n", target_pkg_list.size());
    if(target_pkg_list.empty()) return;

    wait_decrypted_and_run([&target_pkg_list]{
        printf("data user decrypted!\n");
        for (const auto& pkg : target_pkg_list) {
            printf("target pkg: %s\n", pkg.c_str());
            remove_ano_tmp_for_pkg(pkg);
        }
    });
    monitor_pkgs_loop(target_pkg_list);
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("start modify system prop\n");
    persist_data_on_uninstall_restore_permissions();
    pid_t pid = ::fork();
    if (pid == 0) {
        run_script(SYSTEM_PROP_SH);
        _exit(127);
    }
    int status; waitpid(pid, &status, 0);

    spawn_delayed_task(5, [=] {
        daemon_loop();
    });
    return 0;
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    if(!persist_data_on_install_backup_permissions()) return "init backup perm failed";
    android_open_url("tg://resolve?domain=Cycle1337");
    return "";
}

void module_on_uninstall(const char* root_key, const char* module_private_dir) {
    persist_data_on_uninstall_restore_permissions();
}

static std::set<std::string> get_app_list() {
    std::unordered_map<std::string, uint32_t> app_list = android_pkgmap::read_all_pkg_uids_exclude_system();
    std::set<std::string> result;
    for (const auto& kv : app_list) {
        std::string_view pkg = kv.first;
        if (pkg.starts_with("com.")) {
            result.insert(kv.first);
        }
    }
    return result;
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
        if(path == "/getCandidatesPkgJson") resp = json_array_from_set(get_app_list());
        else if(path == "/getTargetPkgJson") kernel_module::read_string_disk_storage("target_pkg_json", resp);
        else if(path == "/setTargetPkgJson") resp = is_ok(kernel_module::write_string_disk_storage("target_pkg_json", body.c_str())) ? "OK" : "FAILED";
        
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
private:
    std::string m_root_key;
};

// SKRoot 模块名片
SKROOT_MODULE_NAME("y700四代过黑名单设备 (free)")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("需要手动添加包名")
SKROOT_MODULE_AUTHOR("Cycle1337")
SKROOT_MODULE_UUID32("rA78uQ0M0YyB27zuWmUJyg6uBciMeCRD")
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/Cycle1337_y700_bypass_update.json")