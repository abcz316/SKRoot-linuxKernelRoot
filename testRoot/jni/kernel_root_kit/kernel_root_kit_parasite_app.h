#ifndef _KERNEL_ROOT_KIT_PARASITE_APP_H_
#define _KERNEL_ROOT_KIT_PARASITE_APP_H_
#include <iostream>
#include <set>
namespace kernel_root {
namespace {
    constexpr const char * k_implant_so_name = "lib_root_server.so";
}

ssize_t parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::set<std::string> &output_so_full_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::set<std::string> &output_so_full_path);

ssize_t parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path);
}
#endif /* _KERNEL_ROOT_KIT_PARASITE_APP_H_ */
