#include <iostream>
#include <unistd.h>
#include <algorithm>
#include <sys/wait.h>
#include <sys/syscall.h>
#include "module_tricky_store.h"

#include "kernel_module_kit_umbrella.h"

#include "file_utils.h"
#include "android_packages_list_utils.h"
#include "tricky_store_daemon.h"

#define MOD_VER "1.4.1-r5"

#define TARGET_TS_DIR "/data/adb/"
#define TARGET_TXT "/data/adb/tricky_store/target.txt"
#define KEYBOX_XML "/data/adb/tricky_store/keybox.xml"
#define TEE_STATUS "/data/adb/tricky_store/tee_status"
#define SERVICE_SH "/data/adb/modules/tricky_store/service.sh"
#define SERVICE_BASE "/data/adb/modules/tricky_store/"

#define HIDE_BOOTLOADER_SH "hide_bootloader.sh"

using namespace file_utils;
using namespace android_pkgmap;

static bool write_target_txt_applist() {
    std::unordered_map<std::string, uint32_t> packages = read_all_pkg_uids_exclude_system();
    printf("thrid package count: %zu\n", packages.size());
    std::stringstream sstr;
    for(auto & pkg : packages) sstr << pkg.first << "\n";
    return write_text_file(TARGET_TXT, sstr.str());
}

static bool get_auto_third_app_toggle() {
    bool enable = false;
    kernel_module::read_bool_disk_storage("auto_third_app_toggle", enable);
    return enable;
}

static bool set_target_txt(const std::string& text);
static bool set_auto_third_app_toggle(bool enable) {
    if(enable) {
        write_target_txt_applist();
    } else {
        set_target_txt("");
    }
    return is_ok(kernel_module::write_bool_disk_storage("auto_third_app_toggle", enable));
}

static bool get_fix_tee_toggle() {
    std::string text;
    read_text_file(TEE_STATUS, text);
    return text == "teeBroken=true";
}

static bool set_fix_tee_toggle(bool enable) {
    return write_text_file(TEE_STATUS, enable ? "teeBroken=true" : "teeBroken=false");
}

static bool get_hide_bootloader_toggle() {
    bool enable = true;
    kernel_module::read_bool_disk_storage("hide_bootloader_toggle", enable);
    return enable;
}

static bool set_hide_bootloader_toggle(bool enable) {
    return is_ok(kernel_module::write_bool_disk_storage("hide_bootloader_toggle", enable));
}

static std::string get_target_txt() {
    std::string text;
    read_text_file(TARGET_TXT, text);
    return text;
}

static bool set_target_txt(const std::string& text) {
    return write_text_file(TARGET_TXT, text);
}

static std::string get_keybox_xml() {
    std::string text;
    read_text_file(KEYBOX_XML, text);
    return text;
}

static bool set_keybox_xml(const std::string& text) {
    return write_text_file(KEYBOX_XML, text);
}

static std::string get_hide_bootloader_script(const std::string& module_private_dir) {
    std::string path = module_private_dir + HIDE_BOOTLOADER_SH;
    std::string script;
    read_text_file(path.c_str(), script);
    return script;
}

static bool set_hide_bootloader_script(const std::string& module_private_dir, const std::string & script) {
    std::string path = module_private_dir + HIDE_BOOTLOADER_SH;
    return write_text_file(path.c_str(), script);
}

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("Hello! module_tricky_store!\n");

    bool auto_third_app_toggle = get_auto_third_app_toggle();
    bool tee_fix_toggle = get_fix_tee_toggle();
    bool hide_bootloader_toggle = get_hide_bootloader_toggle();
    printf("auto_third_app_toggle: %d\n", !!auto_third_app_toggle);
    printf("tee_fix_toggle: %d\n", !!tee_fix_toggle);
    printf("hide_bootloader_toggle: %d\n", !!hide_bootloader_toggle);

    spawn_delayed_task(7, [=] {
        if (auto_third_app_toggle) {
            bool ok = write_target_txt_applist();
            printf("[module_tricky_store] write target.txt applist: %s\n", ok ? "success" : "failed");
        }
        printf("[module_tricky_store] run_script: %s\n", SERVICE_SH);
        // run_script(SERVICE_SH); // DO NOT USE!
        // prevent the sh process from remaining in the background.
        start_tricky_store_daemon_loop(SERVICE_BASE);
    });

    if (hide_bootloader_toggle) {
        spawn_delayed_task(9, [=] {
            std::printf("[module_tricky_store] run hide_bootloader_sh\n");
            run_script(HIDE_BOOTLOADER_SH);
        });
    }
    return 0;
}

static void clear_tricky_store_history_dir() {
    delete_path("/data/adb/tricky_store");
    delete_path("/data/adb/modules");
    ::chmod("/data/adb", 0700);
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    printf("[module_tricky_store] on install\n");
    clear_tricky_store_history_dir();
    std::string my_ts_path = std::string(module_private_dir) + "TS/";
    copy_dir(my_ts_path, TARGET_TS_DIR);
    ::sync();
    return "";
}

void module_on_uninstall(const char* root_key, const char* module_private_dir) {
    printf("[module_tricky_store] on uninstall\n");
    clear_tricky_store_history_dir();
    ::sync();
}

static std::string get_all_props() {
    return run_cmd("resetprop");
}

// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        m_module_private_dir = module_private_dir;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        printf("[module_tricky_store] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getVersion") resp = MOD_VER;
        else if(path == "/getAutoThirdAppToggle") resp = get_auto_third_app_toggle() ? "1" : "0";
        else if(path == "/setAutoThirdAppToggle") resp = set_auto_third_app_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getFixTeeToggle") resp = get_fix_tee_toggle() ? "1" : "0";
        else if(path == "/setFixTeeToggle") resp = set_fix_tee_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getHideBootloaderToggle") resp = get_hide_bootloader_toggle() ? "1" : "0";
        else if(path == "/setHideBootloaderToggle") resp = set_hide_bootloader_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getTargetTxt") resp = get_target_txt();
        else if(path == "/setTargetTxt") resp = set_target_txt(body) ? "OK" : "FAILED";
        else if(path == "/getKeyboxXml") resp = get_keybox_xml();
        else if(path == "/setKeyboxXml") resp = set_keybox_xml(body) ? "OK" : "FAILED";
        else if(path == "/getBootloaderScript") resp = get_hide_bootloader_script(m_module_private_dir);
        else if(path == "/setBootloaderScript") resp = set_hide_bootloader_script(m_module_private_dir, body) ? "OK" : "FAILED";
        else if(path == "/getAllProps") resp = get_all_props();

        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
private:
    std::string m_module_private_dir;
};

// SKRoot 模块名片
SKROOT_MODULE_NAME("Tricky Store")
SKROOT_MODULE_VERSION(MOD_VER)
SKROOT_MODULE_DESC("提供系统证书接管与 TEE 状态修复能力。")
SKROOT_MODULE_AUTHOR("5ec1cff, aviraxp, Cyberenchanter and topjohnwu")
SKROOT_MODULE_UUID32("c3a70f603b48380a611131d29c50aac3")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_tricky_store/update.json")

