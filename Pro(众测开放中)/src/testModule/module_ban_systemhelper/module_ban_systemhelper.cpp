#include "patch_commit_cred.h"
#include "kernel_module_kit_umbrella.h"
#include "android_packages_list_utils.h"
#include "process_utils.h"

#include <cstdio>
#include <string>
#include <unistd.h>

// 默认目标 APP 包名（可通过 WebUI 修改，保存后需重启设备生效）
#define DEFAULT_TARGET_APP_COMM "com.mobiletools.systemhelper"

// 磁盘存储 key：保存用户配置的目标 APP 包名
#define STORAGE_KEY_TARGET_PKG "target_app_pkg"

static std::string get_target_pkg() {
    std::string pkg;
    KModErr err = kernel_module::read_string_disk_storage(STORAGE_KEY_TARGET_PKG, pkg);
    if (is_ok(err) && !pkg.empty()) {
        return pkg;
    }
    return DEFAULT_TARGET_APP_COMM;
}

// 开始修补内核
static KModErr patch_kernel_handler(uint32_t target_uid) {
    uint64_t commit_creds = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("commit_creds", commit_creds));
    printf("commit_creds addr: %p\n", (void*)commit_creds);

    uint32_t cred_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_task_struct_cred_offset(cred_offset));
    printf("cred offset: 0x%x\n", cred_offset);

    uint32_t euid_offset = 0;
    RETURN_IF_ERROR(kernel_module::get_cred_euid_offset(euid_offset));
    printf("euid offset: 0x%x\n", euid_offset);

    PatchBase patchBase(cred_offset, euid_offset);
    PatchCommitCred patchCommitCred(patchBase, commit_creds);
    KModErr err = patchCommitCred.patch_commit_cred(target_uid);
    printf("patch commit_creds ret: %s\n", to_string(err).c_str());
    return err;
}

// SKRoot 模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    std::string target_pkg = get_target_pkg();
    uint32_t target_uid = android_pkgmap::get_uid_for_package(target_pkg);
    printf("%s uid: %u\n", target_pkg.c_str(), target_uid);
    if (target_uid == 0) {
        printf("package not found: %s\n", target_pkg.c_str());
        return 0;
    }
    KModErr err = patch_kernel_handler(target_uid);
    printf("patch_kernel_handler ret: %s\n", to_string(err).c_str());
    if (!is_ok(err)) return -1;

    // hook 成功后杀掉目标进程
    process_utils::kill_pkg_processes(target_pkg);
    // 读扫所有进程 cmdline，确认没有目标包名（包括 "包名:pkg" 形式）才返回 0
    for (int i = 0; i < 5; ++i) {
        if (!process_utils::pkg_present_in_cmdline(target_pkg)) {
            return 0;
        }
        ::usleep(100 * 1000); // 等 100ms 让进程彻底退出
    }
    printf("%s still running, cleanup failed\n", target_pkg.c_str());
    return -1;
}

// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        std::string resp;
        if (path == "/getTargetPkg") resp = get_target_pkg();
        else if (path == "/checkPackage") {
            // "exists": 包名存在（已安装）；"missing": 包名不存在；"error": packages.list 读取失败
            int state = android_pkgmap::package_exists(get_target_pkg());
            resp = (state == 1) ? "exists" : (state == 0 ? "missing" : "error");
        }
        else if (path == "/checkProcess") resp = process_utils::pkg_present_in_cmdline(get_target_pkg()) ? "running" : "stopped";
        else if (path == "/setTargetPkg") resp = is_ok(kernel_module::write_string_disk_storage(STORAGE_KEY_TARGET_PKG, body.c_str())) ? "OK" : "FAILED";
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("禁止SystemHelper运行")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("内核级拦截 SystemHelper APP运行（com.mobiletools.systemhelper 可修改），减少耗电。");
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("rBUTBgYOZ3HC0DHv1gDKRjCgeFcSl7Uk")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
