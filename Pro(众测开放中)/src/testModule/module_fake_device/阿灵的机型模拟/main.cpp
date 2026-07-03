#include <sys/wait.h>
#include "kernel_module_kit_umbrella.h"

#define MODIFY_ANDROID_SECURE_DATE_MODID32 "nv2ZfKbBpBYxYvFqwgcGHEvQkjFjaRvS"

static void android_open_url(const std::string& url) {
    std::string cmd = "am start -a android.intent.action.VIEW -d " + url;
    FILE * fp = popen(cmd.c_str(), "r");
    if(fp) pclose(fp);
}

extern char** environ;

static void exec_script(const char* script) {
    const char* sh = "/system/bin/sh";
    char* const argv[] = {
        const_cast<char*>(sh),
        const_cast<char*>(script),
        nullptr
    };
    execve(sh, argv, environ);
    // execve 成功不会返回，走到这里说明失败
    perror("execve /system/bin/sh failed");
    _exit(127);
}

static int fork_run_script_and_wait(const char* script) {
    pid_t pid = ::fork();
    if (pid < 0) {
        perror("fork failed");
        return -1;
    }
    if (pid == 0) {
        exec_script(script);
        _exit(127); // 理论上不会走到这里，防御一下
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        perror("waitpid failed");
        return -1;
    }
    return status;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    std::string sh;
    kernel_module::read_string_disk_storage("sh", sh);
    printf("*******************************\n");
    printf(" 全局模拟机型: %s\n", sh.c_str());
    printf("   阿灵\n");
    printf("*******************************\n");
    if(sh.empty()) return 0;
    fork_run_script_and_wait(sh.c_str());

    std::vector<skroot_env::module_record> mod_list;
    if(is_ok(skroot_env::get_all_modules_list(root_key, mod_list))) {
        bool found = false;
        for(auto & item : mod_list) {
            if(strcmp(item.desc.id32, MODIFY_ANDROID_SECURE_DATE_MODID32) == 0) {
                found = true;
                break;
            }
        }
        if(!found) {
            std::string secure_sh = sh + ".secure_date.sh";
            fork_run_script_and_wait(secure_sh.c_str());
            printf("run done:%s\n", secure_sh.c_str());
        }
    }
    return 0;
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    android_open_url("tg://resolve?domain=ALING521");
    return "";
}

// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    // 这里的Web服务器仅起到读取、保存配置文件的作用。
    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        std::string resp;
        if(path == "/getCurrentSh") kernel_module::read_string_disk_storage("sh", resp);
        else if(path == "/setCurrentSh") resp = is_ok(kernel_module::write_string_disk_storage("sh", body.c_str())) ? "OK" : "FAILED";
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("阿灵的机型模拟")
SKROOT_MODULE_VERSION("5.2.6")
SKROOT_MODULE_DESC("需要手动选择模拟机型，TG频道:@Whitelist520")
SKROOT_MODULE_AUTHOR("阿灵")
SKROOT_MODULE_ID32("z2rYhJP0gOTKK9lYmXS9sanxw6cIZGYD")
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/aling_fake_dev_update.json")