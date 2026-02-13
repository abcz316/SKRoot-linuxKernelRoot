#pragma once
#include <iostream>
#include <unistd.h>

#include "kernel_module_kit_umbrella.h"
#include "kernel_func_executor_helper.h"

namespace {
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

struct kpath {
    uint64_t mnt = 0;
    uint64_t dentry = 0;
};

struct scoped_kpath {
    scoped_kpath() = default;
    ~scoped_kpath() { reset(); }

    scoped_kpath(const scoped_kpath&) = delete;
    scoped_kpath& operator=(const scoped_kpath&) = delete;
    scoped_kpath(scoped_kpath&&) = delete;
    scoped_kpath& operator=(scoped_kpath&&) = delete;

    void init(uint64_t buf_kaddr, const kpath& p) {
        reset();
        _buf_kaddr = buf_kaddr;
        raw = p;
    }

    void reset() {
        if (!_buf_kaddr) { raw = {}; return; }

        uint64_t kaddr = _buf_kaddr;
        _buf_kaddr = 0;
        raw = {};

        uint64_t r = 0;
        get_kernel_shellcode_u64_result([kaddr](Assembler* a, GpX& x) -> KModErr {
            KModErr err = KModErr::ERR_MODULE_PARAM;
            kernel_module::export_symbol::path_put(a, err, kaddr);
            RETURN_IF_ERROR(err);
            return KModErr::OK;
        }, r);

        kernel_module::free_kernel_mem(kaddr);
    }

    uint64_t release_kaddr() {
        uint64_t kaddr = _buf_kaddr;
        _buf_kaddr = 0;
        raw = {};
        return kaddr;
    }

    kpath raw{};

private:
    uint64_t _buf_kaddr = 0;
};

KModErr acquire_kpath(const std::string & path_str, scoped_kpath & out_scoped) {
    using LookupFlags = kernel_module::export_symbol::LookupFlags;

    int page_size = kernel_module::get_page_size();

    uint64_t buf_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(page_size, buf_kaddr));
    RETURN_IF_ERROR(kernel_module::fill00_kernel_mem(buf_kaddr, page_size));

    uint64_t r = 0;
    RETURN_IF_ERROR(get_kernel_shellcode_u64_result([buf_kaddr, &path_str](Assembler* a, GpX & x) -> KModErr {
        KModErr err = KModErr::ERR_MODULE_PARAM;
        aarch64_asm_set_x_cstr_ptr(a, x10, path_str);
        kernel_module::export_symbol::kern_path(a, err, x10, LookupFlags::LOOKUP_FOLLOW, buf_kaddr);
        RETURN_IF_ERROR(err);
        return KModErr::OK;
    }, r));

    kpath st_kp = {0};
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(buf_kaddr, &st_kp, sizeof(st_kp)));
    out_scoped.init(buf_kaddr, st_kp);
    return KModErr::OK;
}

}
