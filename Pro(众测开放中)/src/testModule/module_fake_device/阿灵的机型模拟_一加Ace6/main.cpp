#include <string>
#include <cstring>
#include <cstdio>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include "kernel_module_kit_umbrella.h"

#define SYSTEM_PROP_SH "system_prop.sh"

static void android_open_url(const std::string& url) {
    std::string cmd = "am start -a android.intent.action.VIEW -d " + url;
    FILE * fp = popen(cmd.c_str(), "r");
    if(fp) pclose(fp);
}

static void run_script(const char* script) {
    const char* sh = "/system/bin/sh";
    char* const argv[] = {
        (char*)sh,
        (char*)script,
        nullptr
    };
    execve(sh, argv, environ);
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("*******************************\n");
    printf(" 全局模拟机型：ACE 6\n");
    printf("   阿灵\n");
    printf("*******************************\n");
    pid_t pid = ::fork();
    if (pid == 0) {
        run_script(SYSTEM_PROP_SH);
        _exit(127);
    }
    int status; waitpid(pid, &status, 0);
    return 0;
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    android_open_url("tg://resolve?domain=ALING521");
    return "";
}

// SKRoot 模块名片
SKROOT_MODULE_NAME("阿灵的机型模拟 一加ACE 6")
SKROOT_MODULE_VERSION("5.2.0")
SKROOT_MODULE_DESC("全局机型模拟为一加ACE 6，TG频道:@Whitelist520")
SKROOT_MODULE_AUTHOR("阿灵")
SKROOT_MODULE_UUID32("Pr596Oi52bfandlOpzjPIWGIHEK0YYCo")
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/aling_oneplus_ace6_update.json")