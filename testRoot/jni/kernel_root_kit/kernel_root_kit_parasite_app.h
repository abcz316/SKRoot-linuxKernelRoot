#ifndef _KERNEL_ROOT_KIT_PARASITE_APP_H_
#define _KERNEL_ROOT_KIT_PARASITE_APP_H_
#include <iostream>
#include <set>
namespace kernel_root {
namespace {
    constexpr const char * k_implant_root_server_so_name = "lib_root_server.so";
    constexpr const char * k_implant_su_env_so_name = "lib_su_env.so";
    constexpr const char * k_implant_so_name_arr[] = {k_implant_root_server_so_name, k_implant_su_env_so_name};

}
enum app_so_status {
    unknow = 0,
    running,
    not_running
};

ssize_t parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, app_so_status> &output_so_full_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, app_so_status> &output_so_full_path);

ssize_t parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path);

ssize_t parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, std::string_view su_folder);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, std::string_view su_folder);
}
#endif /* _KERNEL_ROOT_KIT_PARASITE_APP_H_ */
