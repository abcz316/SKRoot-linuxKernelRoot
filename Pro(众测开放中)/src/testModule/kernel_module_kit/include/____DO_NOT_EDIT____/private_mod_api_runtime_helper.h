#pragma once
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "../module_err_def.h"
namespace kernel_module {
inline KModErr execute_kernel_asm_func(const std::vector<uint8_t>& func_bytes, uint64_t& output_result) {
    KModErr execute_kernel_asm_func_with_buf(const uint8_t*shellcode, uint32_t size, uint64_t& out_kaddr);
    return execute_kernel_asm_func_with_buf(func_bytes.data(), func_bytes.size(), output_result);
}

inline KModErr read_string_disk_storage(const char* key, std::string& out) {
    thread_local std::string* tls_out = nullptr;
    auto cb = [](const char* out_str) {
        if (!tls_out || !out_str) return;
        (*tls_out) = out_str;
    };
    tls_out = &out;
    KModErr read_string_disk_storage_with_cb(const char* key, void (*cb)(const char* out_str));
    KModErr err = read_string_disk_storage_with_cb(key, cb);
    tls_out = nullptr; 
    return err;
}

inline KModErr read_blob_disk_storage(const char* key, std::vector<uint8_t>& out) {
    thread_local std::vector<uint8_t>* tls_out = nullptr;
    auto cb = [](const void* data, uint64_t size) {
        if (!tls_out || !data) return;
        const uint8_t* p = static_cast<const uint8_t*>(data);
        tls_out->assign(p, p + size);
    };
    tls_out = &out;
    KModErr read_blob_disk_storage_with_cb(const char* key, void (*cb)(const void* data, uint64_t size));
    KModErr err = read_blob_disk_storage_with_cb(key, cb);
    tls_out = nullptr; 
    return err;
}

// 详情请跳转：module_base_kernel_func_hook.h
inline KModErr install_kernel_function_before_hook(uint64_t kaddr, const std::vector<uint8_t>& hook_handler_code) {
    KModErr install_kfunc_before_hook_with_buf(uint64_t hook_kaddr, const void *shellcode, uint32_t shellcode_len);
    return install_kfunc_before_hook_with_buf(kaddr, hook_handler_code.data(), hook_handler_code.size());
}

// 详情请跳转：module_base_kernel_func_hook.h
inline KModErr install_kernel_function_after_hook(uint64_t target_func_kaddr, const std::vector<uint8_t>& hook_handler_code) {
    KModErr install_kfunc_after_hook_with_buf(uint64_t hook_kaddr, const void *shellcode, uint32_t shellcode_len);
    return install_kfunc_after_hook_with_buf(target_func_kaddr, hook_handler_code.data(), hook_handler_code.size());
}
}