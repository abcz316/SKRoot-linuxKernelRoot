#include <iostream>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <thread>
#include <sys/wait.h>
#include <sys/syscall.h>
#include "module_TEESimulatorRS.h"

#include "kernel_module_kit_umbrella.h"

#include "file_utils.h"
#include "android_packages_list_utils.h"
#include "android_system_property_utils.h"

#define MOD_VER "6.0.1-r3"

#define CONFIG_DIR "/data/adb/tricky_store"
#define TARGET_TXT "/data/adb/tricky_store/target.txt"
#define KEYBOX_XML "/data/adb/tricky_store/keybox.xml"
#define TEE_STATUS "/data/adb/tricky_store/tee_status"
#define HIDE_BOOTLOADER_SH "hide_bootloader.sh"
#define SERVICE_SH "TEESimulatorRS_Core/service.sh"

using namespace file_utils;
using namespace android_pkgmap;
namespace fs = std::filesystem;

static constexpr const char* k_security_patch_property_keys[] = {
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
    "ro.system.build.version.security_patch",
    "ro.product.build.version.security_patch",
    "ro.system_ext.build.version.security_patch",
    "ro.odm.build.version.security_patch",
    "ro.odm.build.security_patch",
    "ro.bootimage.build.version.security_patch",
    "ro.vendor_dlkm.build.version.security_patch",
    "ro.odm_dlkm.build.version.security_patch",
    "ro.system_dlkm.build.version.security_patch",
};

static bool write_target_txt_applist() {
    std::unordered_map<std::string, uint32_t> packages = read_all_pkg_uids_exclude_system();
    printf("thrid package count: %zu\n", packages.size());
    std::stringstream sstr;
    for(auto & pkg : packages) sstr << pkg.first << "\n";
    return write_text_file(TARGET_TXT, sstr.str());
}

static bool get_auto_third_app_toggle() {
    bool enable = true;
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
    return text == "tee_broken=true";
}

static bool set_fix_tee_toggle(bool enable) {
    return write_text_file(TEE_STATUS, enable ? "tee_broken=true" : "tee_broken=false");
}

static bool get_hide_bootloader_toggle() {
    bool enable = true;
    kernel_module::read_bool_disk_storage("hide_bootloader_toggle", enable);
    return enable;
}

static bool set_hide_bootloader_toggle(bool enable) {
    return is_ok(kernel_module::write_bool_disk_storage("hide_bootloader_toggle", enable));
}

static std::string get_android_security_patch_date() {
    for (const char* key : k_security_patch_property_keys) {
        const std::string old_value = get_system_property(key);
        if(!old_value.empty()) return old_value;
    }
    return {};
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
    printf("Hello! module_TEESimulatorRS!\n");

    bool auto_third_app_toggle = get_auto_third_app_toggle();
    bool tee_fix_toggle = get_fix_tee_toggle();
    bool hide_bootloader_toggle = get_hide_bootloader_toggle();
    printf("auto_third_app_toggle: %d\n", !!auto_third_app_toggle);
    printf("tee_fix_toggle: %d\n", !!tee_fix_toggle);
    printf("hide_bootloader_toggle: %d\n", !!hide_bootloader_toggle);
    
    create_directory_if_not_exists(CONFIG_DIR);

    if (hide_bootloader_toggle) {
        std::printf("run hide_bootloader.sh\n");
        fork_run_script_and_wait(HIDE_BOOTLOADER_SH);
    }

    if (auto_third_app_toggle) {
        bool ok = write_target_txt_applist();
        printf("write target.txt applist: %s\n", ok ? "success" : "failed");
        pid_t pid = ::fork();
        if (pid == 0) {
            sleep(7);
            static std::atomic_bool stop_watcher{false};
            android_pkgmap::watch_packages_list_changed([] {
                printf("app list has changed!\n");
                bool ok = write_target_txt_applist();
                printf("write target.txt applist: %s\n", ok ? "success" : "failed");
            }, stop_watcher);
            _exit(127);
        }
    }

    pid_t pid = ::fork();
    if (pid == 0) {
        const fs::path service_path = fs::path(module_private_dir) / SERVICE_SH;
        exec_script(service_path.c_str());
        _exit(127);
    }
    return 0;
}

static void clear_TEESimulatorRS_history_dir() {
    delete_path("/data/adb/tricky_store");
    ::chmod("/data/adb", 0700);
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    printf("[module_TEESimulatorRS] on install\n");
    clear_TEESimulatorRS_history_dir();
    ::sync();
    return "";
}

void module_on_uninstall(const char* root_key, const char* module_private_dir) {
    printf("[module_TEESimulatorRS] on uninstall\n");
    clear_TEESimulatorRS_history_dir();
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
        printf("[module_TEESimulatorRS] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getVersion") resp = MOD_VER;
        else if(path == "/getAutoThirdAppToggle") resp = get_auto_third_app_toggle() ? "1" : "0";
        else if(path == "/setAutoThirdAppToggle") resp = set_auto_third_app_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getFixTeeToggle") resp = get_fix_tee_toggle() ? "1" : "0";
        else if(path == "/setFixTeeToggle") resp = set_fix_tee_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getHideBootloaderToggle") resp = get_hide_bootloader_toggle() ? "1" : "0";
        else if(path == "/setHideBootloaderToggle") resp = set_hide_bootloader_toggle(body == "1") ? "OK" : "FAILED";
        else if(path == "/getAndroidSecurityPatchDate") resp = get_android_security_patch_date();
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
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("TEESimulator-RS")
SKROOT_MODULE_VERSION(MOD_VER)
SKROOT_MODULE_DESC("Software simulation for Android hardware-backed key pairs with key attestation")
SKROOT_MODULE_AUTHOR("JingMatrix, Enginex0, xiaoxun")
SKROOT_MODULE_ID32("teesimulator601skpro202607210000")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_TEESimulatorRS/update.json")

