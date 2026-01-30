#pragma once
#include <optional>
#include <vector>
#include <string>
#include <unistd.h>
#include "../module_err_def.h"
#include "../skroot_env/skroot_module.h"
#include "../skroot_env/skroot_su_auth.h"
#include "../skroot_env/skroot_test.h"
namespace skroot_env {
inline KModErr read_skroot_log(const char* root_key, std::string& out) {
    thread_local std::string* tls_out = nullptr;
    auto cb = [](const char* text) {
        if (!tls_out) return;
        (*tls_out) = text;
    };
    tls_out = &out;
    KModErr read_skroot_log_cb(const char* root_key, void (*cb)(const char* text));
    KModErr err = read_skroot_log_cb(root_key, cb);
    tls_out = nullptr; 
    return err;
}

inline KModErr get_all_modules_list(const char* root_key, std::vector<module_desc>& out_list, ModuleListMode mode) {
    thread_local std::vector<module_desc>* tls_out = nullptr;
    auto cb = [](const module_desc* desc) {
        if (!tls_out || !desc) return;
        module_desc d;
        std::memcpy(&d, desc, sizeof(d));
        tls_out->push_back(std::move(d));
    };
    tls_out = &out_list;
    KModErr get_all_modules_with_cb(const char* root_key, void (*cb)(const module_desc* desc), ModuleListMode mode);
    KModErr err = get_all_modules_with_cb(root_key, cb, mode);
    tls_out = nullptr; 
    return err;
}

inline KModErr install_module(const char* root_key, const char* module_zip_path, std::string& out_reason) {
    thread_local std::string* tls_out = nullptr;
    auto cb = [](const char* text) {
        if (!tls_out) return;
        (*tls_out) = text;
    };
    tls_out = &out_reason;
    KModErr install_module_with_cb(const char* root_key, const char* module_zip_path, void (*cb)(const char* reason));
    KModErr err = install_module_with_cb(root_key, module_zip_path, cb);
    tls_out = nullptr;
    return err;
}

inline KModErr get_su_auth_list(const char* root_key, std::vector<su_auth_item>& out_pkgs) {
    thread_local std::vector<su_auth_item>* tls_out = nullptr;
    auto cb = [](const su_auth_item* item) {
        if (!tls_out || !item) return;
        su_auth_item s;
        std::memcpy(&s, item, sizeof(s));
        tls_out->push_back(std::move(s));
    };
    tls_out = &out_pkgs;
    KModErr get_su_auth_list_with_cb(const char* root_key, void (*cb)(const su_auth_item* item));
    KModErr err = get_su_auth_list_with_cb(root_key, cb);
    tls_out = nullptr; 
    return err;
}


inline KModErr test_skroot_basics(const char* root_key, BasicItem item, std::string& out) {
    thread_local std::string* tls_out = nullptr;
    auto cb = [](const char* text) {
        if (!tls_out) return;
        (*tls_out) = text;
    };
    tls_out = &out;
    KModErr test_skroot_basics_with_cb(const char* root_key, BasicItem item, void (*cb)(const char* out_str));
    KModErr err = test_skroot_basics_with_cb(root_key, item, cb);
    tls_out = nullptr; 
    return err;
}

inline KModErr test_skroot_deafult_module(const char* root_key, DeafultModuleName name, std::string& out) {
    thread_local std::string* tls_out = nullptr;
    auto cb = [](const char* text) {
        if (!tls_out) return;
        (*tls_out) = text;
    };
    tls_out = &out;
    KModErr test_skroot_deafult_module_with_cb(const char* root_key, DeafultModuleName name, void (*cb)(const char* out_str));
    KModErr err = test_skroot_deafult_module_with_cb(root_key, name, cb);
    tls_out = nullptr; 
    return err;
}

}