#pragma once
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "../../module_err_def.h"
#include "../../module_base_kernel_func_hook.h"
namespace kernel_module {
inline KModErr execute_kernel_asm_func(const std::vector<uint8_t>& func_bytes, uint64_t& output_result) {
    KModErr execute_kernel_asm_func_with_buf(const uint8_t*shellcode, uint32_t shellcode_len, uint64_t& out_kaddr);
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

inline void set_current_module_description(const std::string& new_description) {
    void set_current_module_description_with_str(const char* new_description);
    set_current_module_description_with_str(new_description.c_str());
}

// 详情请跳转：module_base_kernel_func_hook.h
inline KModErr install_kernel_function_before_hook(uint64_t kaddr, const std::vector<uint8_t>& handler_shellcode, HookHandle* out_hook_handle) {
    KModErr install_kfunc_before_hook_with_buf(uint64_t hook_kaddr, const void *shellcode, uint32_t shellcode_len, HookHandle* out_hook_handle);
    return install_kfunc_before_hook_with_buf(kaddr, handler_shellcode.data(), handler_shellcode.size(), out_hook_handle);
}

// 详情请跳转：module_base_kernel_func_hook.h
inline KModErr install_kernel_function_after_hook(uint64_t target_func_kaddr, const std::vector<uint8_t>& handler_shellcode, HookHandle* out_hook_handle) {
    KModErr install_kfunc_after_hook_with_buf(uint64_t hook_kaddr, const void *shellcode, uint32_t shellcode_len, HookHandle* out_hook_handle);
    return install_kfunc_after_hook_with_buf(target_func_kaddr, handler_shellcode.data(), handler_shellcode.size(), out_hook_handle);
}
}
void set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(bool enable);
bool get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3();

class SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 final {
public:
    SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703() noexcept { 
        active_ = get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3();
        if (active_) set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(false);
    }
    ~SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703() noexcept { if (active_) set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(true); }
    DISABLE_COPY_MOVE(SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703);
private:
    bool active_ = false;
};