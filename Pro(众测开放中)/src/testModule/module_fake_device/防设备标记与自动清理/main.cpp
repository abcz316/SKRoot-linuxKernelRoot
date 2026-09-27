#include <set>
#include <unordered_map>
#include <vector>

#include "persist_dir_perm_manager.h"

#include "utils/third_party/cJSON.h"
#include "utils/android_packages_list_utils.h"
#include "utils/boot_session_utils.h"
#include "utils/file_utils.h"
#include "utils/json_helper.h"
#include "utils/pkg_process_helper.h"
#include "utils/app_label_helper/app_label_helper_data.generated.h"
#include "utils/app_label_helper/app_label_helper.h"

using namespace file_utils;

std::string g_root_key;
static volatile sig_atomic_t g_need_reload = 0;
PersistDirPermManager g_persist_dir_perm_manager;

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
        if (!process_utils::is_all_digits(uid)) continue;

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
        if (!process_utils::is_all_digits(uid)) continue;

        fs::path ano_tmp = entry.path() / pkg / "files" / "ano_tmp";
        if (fs::exists(ano_tmp, ec) && !ec && fs::is_directory(ano_tmp, ec) && !ec) {
            hit_any = true;
            fs::remove_all(ano_tmp, ec);
            printf("remove ano_tmp success: %s\n", pkg.c_str());
        }
    }
    return hit_any;
}

static bool set_persist_dir_locked_once(bool should_lock) {
    static bool s_locked = false;
    if (should_lock) {
        if (s_locked) return true;
        if (!g_persist_dir_perm_manager.lock()) return false;
        s_locked = true;
        return true;
    }

    if (!s_locked) return true;
    if (!g_persist_dir_perm_manager.unlock()) return false;
    s_locked = false;
    return true;
}

static void monitor_pkgs_loop(const std::set<std::string>& pkgs) {
    using namespace std::chrono_literals;
    static std::map<std::string, bool> s_pkg_remove_armed;
    for (;;) {
        bool any_running = false;
        for (const auto& pkg : pkgs) {
            const bool running = is_pkg_running(pkg, 200 * 1024); // 忽略200MB以下的
            if (running) {
                any_running = true;
                if(!s_pkg_remove_armed[pkg]) printf("detect running:%s\n", pkg.c_str());
                s_pkg_remove_armed[pkg] = true;
                continue;
            }
            bool& remove_armed = s_pkg_remove_armed[pkg];
            if (remove_armed) {
                printf("detect close:%s\n", pkg.c_str());
                remove_ano_tmp_for_pkg(pkg);
                remove_armed = false;
            }
        }
        set_persist_dir_locked_once(any_running && !g_need_reload);
        if(g_need_reload) break;
        std::this_thread::sleep_for(2s);
    }
}

static void daemon_loop() {
    printf("start daemon loop, pid=%ld\n", static_cast<long>(getpid()));
    std::string json;
    kernel_module::read_string_disk_storage("target_pkg_json", json);
    std::set<std::string> target_pkg_list = parse_json(json);
    printf("target pkg list (%zu total), top 5:\n", target_pkg_list.size());
    size_t max_count = target_pkg_list.size() > 5 ? 5 : target_pkg_list.size();
    auto it = target_pkg_list.begin();
    for (size_t i = 0; i < max_count; ++i, ++it) {
        printf("%s\n", it->c_str());
    }
    kernel_module::write_int32_disk_storage("pid", (int)getpid());
    kernel_module::write_string_disk_storage("boot_session", boot_session_utils::read_boot_session().c_str());
    wait_decrypted_and_run([&target_pkg_list]{
        printf("data user decrypted!\n");
        sleep(10);
        kill_pkg_list_until_stopped(target_pkg_list);
        for (const auto& pkg : target_pkg_list) {
            printf("target pkg: %s\n", pkg.c_str());
            remove_ano_tmp_for_pkg(pkg);
        }
        monitor_pkgs_loop(target_pkg_list);
    });
}

static void on_sigusr1(int signo) {
    (void)signo;
    const char msg[] = "recv signUser1: reload pkgs\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1); 
    g_need_reload = 1;
}

static void register_sigusr1() {
    struct sigaction sa = {};
    sa.sa_handler = on_sigusr1;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, nullptr);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &set, nullptr);
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    g_root_key = root_key;
    if(!g_persist_dir_perm_manager.init()) {
        printf("persist_dir_perm_manager init failed\n");
        return -1;
    }
    process_utils::fork_delayed_task(5, [=] {
        skroot_env::get_root(g_root_key.c_str());
        register_sigusr1();
        daemon_loop();
        while(g_need_reload) { g_need_reload = 0; daemon_loop(); }
    });
    return 0;
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    if (file_exists("/mnt/vendor/nvdata")) {
        kernel_module::set_current_module_description(
            "需手动添加目标包名。判断开启成功：/mnt/vendor/nvdata (天玑)目录下文件为空、无法写入文件，表示拦截已生效。本模块采用内核拦截技术，不改目录权限。支持天玑，天玑安装后显示新路径。");
    }
    return "";
}

// 返回候选包列表 JSON：{"content":[{"packageName":"...","labelBase64":"..."}]}
static std::string get_app_list_json(const std::string& root_key, const std::string& work_dir) {
    std::unordered_map<std::string, uint32_t> packageNames = android_pkgmap::read_all_pkg_uids_exclude_system();
    std::map<std::string, std::string> display_names = app_label_helper::get_all_app_display_names(root_key.c_str(), work_dir.c_str(), kernel_module::app_label_helper_file_data, kernel_module::app_label_helper_file_size);

    std::vector<std::pair<std::string, std::string>> appList;
    for (const auto& kv : packageNames) {
        if (!kv.first.starts_with("com.")) continue;
        auto it = display_names.find(kv.first);
        appList.push_back({kv.first, (it != display_names.end()) ? it->second : ""});
    }
    return convert_2_json_app_list(appList);
}

// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        (void)port;
        m_root_key = root_key;
        m_module_private_dir = module_private_dir;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        printf("[module_hide_data_dir] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getCandidatesPkgJson") resp = get_app_list_json(m_root_key, m_module_private_dir);
        else if(path == "/getTargetPkgJson") kernel_module::read_string_disk_storage("target_pkg_json", resp);
        else if(path == "/setTargetPkgJson") resp = onSetTargetPkgJson(body);
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }

private:
    std::string m_root_key;
    std::string m_module_private_dir;

    std::string onSetTargetPkgJson(const std::string& body) {
        bool write_ok = is_ok(kernel_module::write_string_disk_storage("target_pkg_json", body.c_str()));
        if (!write_ok) {
            printf("write target_pkg_json failed\n");
            return "FAILED";
        }
        std::string boot_session;
        kernel_module::read_string_disk_storage("boot_session", boot_session);

        std::string current_boot_session = boot_session_utils::read_boot_session();
        if (boot_session != current_boot_session) {
            printf("boot_session mismatch, saved=%s, current=%s\n", boot_session.c_str(), current_boot_session.c_str());
            return "FAILED";
        }
        
        int32_t pid = 0;
        kernel_module::read_int32_disk_storage("pid", pid);
        if (pid <= 0) {
            printf("invalid daemon pid, pid=%d\n", pid);
            return "FAILED";
        }

        if (!process_utils::is_pid_root(pid)) {
            printf("daemon pid is not root or not alive, pid=%d\n", pid);
            return "FAILED";
        }
        printf("send SIGUSR1 to daemon, pid=%d\n", pid);

        if (::kill(pid, SIGUSR1) == 0) {
            printf("send SIGUSR1 success, pid=%d\n", pid);
            return "OK";
        }
        int err = errno;
        printf("kill SIGUSR1 failed, pid=%d, errno=%d, err=%s\n", pid, err, strerror(err));
        return "FAILED";
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("防设备标记&自动清理")
SKROOT_MODULE_VERSION("5.0.6")
SKROOT_MODULE_DESC("需手动添加目标包名。判断开启成功：/mnt/vendor/persist/data (高通)目录下文件为空、无法写入文件，表示拦截已生效。本模块采用内核拦截技术，不改目录权限。支持天玑。防标记工作时，指纹支付App可能报异常。")
SKROOT_MODULE_AUTHOR("SKRoot & 蜃 & Cycle1337")
SKROOT_MODULE_ID32("Vk0EFJTuG2aBLQqc6WLHVPHnhfiZ8VKG")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/cycle1337_bypass_device_flag_update.json")