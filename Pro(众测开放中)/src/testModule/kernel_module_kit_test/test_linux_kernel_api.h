#include "kernel_module_kit_test.h"
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;


KModErr Test_kallsyms_lookup_name1() {
    uint64_t kaddr = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("kernel_halt", kaddr));
    printf("kallsyms_lookup_name1 output addr: %p\n", (void*)kaddr);
    return KModErr::OK;
}

KModErr Test_kallsyms_lookup_name2() {
    using SymbolMatchMode = kernel_module::SymbolMatchMode;
    using SymbolHit = kernel_module::SymbolHit;


    SymbolHit hit;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("kernel_resta", hit, SymbolMatchMode::Prefix));
    printf("kallsyms_lookup_name2 hit name:%s, addr: %p\n", hit.name, (void*)hit.addr);
    return KModErr::OK;
}

KModErr Test_get_symbol_size() {
    uint64_t kaddr = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("kernel_halt", kaddr));

    uint64_t symbol_size = 0;
    KModErr err = kernel_module::get_symbol_size(kaddr, symbol_size);
    printf("get_symbol_size return: %s, addr: %p, size: 0x%llx\n", to_string(err).c_str(), (void*)kaddr, (unsigned long long)symbol_size);
    return err;
}

KModErr Test_get_task_mm() {
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([](Assembler* a, GpX& out_result_reg) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        kernel_module::export_symbol::get_current(a, x1);
        kernel_module::export_symbol::get_task_mm(a, err, x1);
        RETURN_FALSE_IF_ERROR(err);
        kernel_module::export_symbol::mmput(a, err, x0);
        RETURN_FALSE_IF_ERROR(err);
        aarch64_asm_mov_x(a, x0, 0x4567);
        out_result_reg = x0;
        return true;
    }, result));
    printf("get_task_mm + mmput result: %s\n", result == 0x4567 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_printk() {
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([](Assembler* a, GpX& out_result_reg) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x0, 0x4567);
        kernel_module::export_symbol::printk(a, err, "[!!!] my_printk:%d\n", x0);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, result));
    printf("printk result: %s\n", result == 0x4567 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_copy_from_user() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::fill00_kernel_mem(addr, 1024));
    const char * str = "abc123456789abcdefg";
    uint64_t ret = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([addr, str](Assembler* a, GpX& out_result_reg) -> bool {
        aarch64_asm_mov_x(a, x1, addr);
        aarch64_asm_mov_x(a, x2, (uint64_t)str);
        aarch64_asm_mov_x(a, x3, 10);
        KModErr err = KModErr::ERR_MODULE_ASM;
        kernel_module::export_symbol::copy_from_user(a, err, x1, x2, x3);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, ret));
    if(ret == 0) {
        std::vector<uint8_t> buf(11);
        RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
        buf.push_back(0);
        std::string s(reinterpret_cast<const char*>(buf.data()));
        printf("copy_from_user result: %s\n", s == "abc1234567" ? "ok" : "failed");
    } else {
        printf("copy_from_user result: failed\n");
    }
    return KModErr::OK;
}

KModErr Test_copy_to_user() {
    char str[] = "yyyyyyyyyyyyyyyc";
    uint64_t r = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([str](Assembler* a, GpX& out_result_reg) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x11, (uint64_t)str);
        aarch64_asm_set_x_cstr_ptr(a, x12, "abc123456789abcdefghijk");
        aarch64_asm_mov_x(a, x13, 15);
        kernel_module::export_symbol::copy_to_user(a, err, x11, x12, x13);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, r));
    printf("copy_to_user result: %s\n", std::string(str) == "abc123456789abcc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmalloc1() {
    using namespace kernel_module::export_symbol;
    uint64_t ret = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([](Assembler* a, GpX& out_result_reg) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x1, 128);
        kernel_module::export_symbol::kmalloc(a, err, x1, KmallocFlags::GFP_KERNEL);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, ret));
    if(ret != 0) {
        RETURN_IF_ERROR(kernel_module::write_kernel_mem(ret, (void*)"123456789aaa", sizeof("123456789aaa")));
        std::vector<uint8_t> buf(sizeof("123456789aaa"));
        RETURN_IF_ERROR(kernel_module::read_kernel_mem(ret, buf.data(), buf.size()));
        buf.push_back(0);
        std::string s(reinterpret_cast<const char*>(buf.data()));
        printf("kmalloc1 result: %s\n", s == "123456789aaa" ? "ok" : "failed");
    } else {
        printf("kmalloc1 result: failed\n");
    }
    return KModErr::OK;
}

KModErr Test_kfree1() {
    using namespace kernel_module::export_symbol;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode([](Assembler* a) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x1, 128);
        kernel_module::export_symbol::kmalloc(a, err, x1, KmallocFlags::GFP_KERNEL);
        RETURN_FALSE_IF_ERROR(err);
        kernel_module::export_symbol::kfree(a, err, x0);
        RETURN_FALSE_IF_ERROR(err);
        return true;
    }));
    printf("kfree1 result: ok\n");
    return KModErr::OK;
}

KModErr Test_kmalloc2() {
    using namespace kernel_module::export_symbol;
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::kmalloc(1024, KmallocFlags::GFP_KERNEL, addr));
    printf("kmalloc2 addr: %p\n", (void*)addr);
    printf("kmalloc2 result: %s\n", addr ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kfree2() {
    using namespace kernel_module::export_symbol;
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::kmalloc(1024, KmallocFlags::GFP_KERNEL, addr));
    RETURN_IF_ERROR(kernel_module::export_symbol::kfree(addr));
    printf("kfree2 result: ok\n");
    return KModErr::OK;
}

KModErr Test_module_alloc1() {
    uint64_t ret = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([](Assembler* a, GpX& out_result_reg) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x1, 128);
        kernel_module::export_symbol::linux_older::module_alloc(a, err, x1);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, ret));

    if(ret != 0) {
        RETURN_IF_ERROR(kernel_module::write_kernel_mem(ret, (void*)"123456789aaa", sizeof("123456789aaa")));
        std::vector<uint8_t> buf(sizeof("123456789aaa"));
        RETURN_IF_ERROR(kernel_module::read_kernel_mem(ret, buf.data(), buf.size()));
        buf.push_back(0);
        std::string s(reinterpret_cast<const char*>(buf.data()));
        printf("module_alloc1 result: %s\n", s == "123456789aaa" ? "ok" : "failed");
    } else {
        printf("module_alloc2 result: failed\n");
    }
    return KModErr::OK;
}

KModErr Test_module_memfree1() {
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode([](Assembler* a) -> bool {
        KModErr err = KModErr::ERR_MODULE_ASM;
        aarch64_asm_mov_x(a, x1, 128);
        kernel_module::export_symbol::linux_older::module_alloc(a, err, x1);
        RETURN_FALSE_IF_ERROR(err);
        kernel_module::export_symbol::linux_older::module_memfree(a, err, x0);
        RETURN_FALSE_IF_ERROR(err);
        return true;
    }));
    printf("module_memfree1 result: ok\n");
    return KModErr::OK;
}

KModErr Test_module_alloc2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::linux_older::module_alloc(1024, addr));
    printf("module_alloc2 addr: %p\n", (void*)addr);
    printf("module_alloc2 result: %s\n", addr ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_module_memfree2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::linux_older::module_alloc(1024, addr));
    RETURN_IF_ERROR(kernel_module::export_symbol::linux_older::module_memfree(addr));
    printf("module_memfree2 result: ok\n");
    return KModErr::OK;
}

// static void emit_cb(Assembler* a, GpX data, GpX name_ptr, GpX mod, GpX addr) {
//     KModErr err = KModErr::OK;
//     kernel_module::export_symbol::printk(a, err, "[!!!!] kallsyms_symbol:%s, addr:%llx\n", name_ptr, addr);
//     a->mov(x0, xzr); // continue next
// }

// KModErr Test_kallsyms_on_each_symbol1() {
//     uint64_t result = 0;
//     RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([](Assembler* a, GpX& out_result_reg) -> KModErr {
//     KModErr err = KModErr::OK;
//     kernel_module::export_symbol::kmalloc(a, err, 1, kernel_module::export_symbol::KmallocFlags::GFP_KERNEL);
//     RETURN_IF_ERROR(err);
//     a->mov(x11, x0);
//     a->strb(wzr, ptr(x11));

//     kernel_module::export_symbol::kallsyms_on_each_symbol(a, err, emit_cb, x11);
//     RETURN_IF_ERROR(err);
//     kernel_module::export_symbol::kfree(a, err, x11);
//     RETURN_IF_ERROR(err);
//     out_result_reg = x0;
//     return KModErr::OK;
//     }, result));
//     printf("kallsyms_on_each_symbol1 result: ok\n");
//     return KModErr::OK;
// }

// struct TLSKsymState2 {
// 	const char* symbol_name_buf = nullptr;
// };

// static thread_local TLSKsymState2 g_tls_ksym2;
// static void emit_cb_tls2(Assembler* a, GpX data, GpX name_ptr, GpX mod, GpX addr) {
//     KModErr err = KModErr::OK;
//     IdleRegPool pool = IdleRegPool::make(data, name_ptr, mod, addr);
//     GpX xMyKeyName = pool.acquireX();
//     GpX xCopyTo = pool.acquireX();
//     GpX xResult = pool.acquireX();
//     GpX xLen = pool.acquireX();
//     GpW wFlag = pool.acquireW();

// 	RegProtectGuard g1(a, excluding_x0(pool.getUsed()));

//     Label L_end = a->newLabel();
//     Label L_continue_next = a->newLabel();

//     a->mov(xResult, Imm(1)); // default stop
//     a->ldrb(wFlag, ptr(data));
//     a->cbnz(wFlag, L_end);
    
//     aarch64_asm_set_x_cstr_ptr(a, xMyKeyName, "kernel_resta");
//     kernel_module::string_ops::kstartswith(a, name_ptr, xMyKeyName);
//     a->cbz(x0, L_continue_next);
    
//     kernel_module::string_ops::kstrlen(a, name_ptr);
//     a->mov(xLen, x0);
//     aarch64_asm_mov_x(a, xCopyTo, (uint64_t)g_tls_ksym2.symbol_name_buf);
//     kernel_module::export_symbol::copy_to_user(a, err, xCopyTo, name_ptr, xLen);

//     a->mov(wFlag, Imm(1));
//     a->strb(wFlag, ptr(data));
//     a->b(L_end);

//     a->bind(L_continue_next);
//     a->mov(xResult, xzr);
    
//     a->bind(L_end);
//     a->mov(x0, xResult);
// }

// KModErr Test_kallsyms_on_each_symbol2() {
//     char symbol_name_buf[1024] = {0};
//     KModErr err = KModErr::OK;
//     uint64_t r = 0;
//     err = kernel_module::run_kernel_shellcode_result_u64([&](Assembler* a, GpX& out_result_reg) -> KModErr {
//     KModErr cb_err = KModErr::OK;
//     kernel_module::export_symbol::kmalloc(a, cb_err, 1, kernel_module::export_symbol::KmallocFlags::GFP_KERNEL);
//     RETURN_IF_ERROR(cb_err);
//     a->mov(x11, x0);
//     a->strb(wzr, ptr(x11));

//     memset(&g_tls_ksym2, 0, sizeof(g_tls_ksym2));
//     g_tls_ksym2.symbol_name_buf = symbol_name_buf;
//     kernel_module::export_symbol::kallsyms_on_each_symbol(a, cb_err, emit_cb_tls2, x11);

//     RETURN_IF_ERROR(cb_err);
//     kernel_module::export_symbol::kfree(a, cb_err, x11);
//     RETURN_IF_ERROR(cb_err);
//     out_result_reg = x0;
//     return KModErr::OK;
//     }, r);
//     RETURN_IF_ERROR(err);

//     std::string_view hay{symbol_name_buf};
//     std::string_view needle{"kernel_resta"};
//     bool ok = hay.size() >= needle.size() && hay.compare(0, needle.size(), needle) == 0;
//     printf("kallsyms_on_each_symbol2 name: %s\n", std::string(symbol_name_buf).c_str());
//     printf("kallsyms_on_each_symbol2 result: %s\n", ok ? "ok" : "failed");
//     return KModErr::OK;
// }

KModErr Test_kern_path() {
    using LookupFlags = kernel_module::export_symbol::LookupFlags;
    uint64_t path_buf_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(0x1000, path_buf_kaddr));

    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([path_buf_kaddr](Assembler* a, GpX& out_result_reg) -> bool {
        aarch64_asm_set_x_cstr_ptr(a, x0, "/data/bhuvsUdRKoCLH3OB/init");

        KModErr err = KModErr::ERR_MODULE_ASM;
        kernel_module::export_symbol::kern_path(a, err, x0, LookupFlags::LOOKUP_FOLLOW, path_buf_kaddr);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, result));
    printf("kern_path output result: %p\n", (void*)result);
    return KModErr::OK;
}

KModErr Test_security_secctx_to_secid() {
    uint64_t result_sid_buf_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(4, result_sid_buf_kaddr));

    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::run_kernel_shellcode_result_u64([result_sid_buf_kaddr](Assembler* a, GpX& out_result_reg) -> bool {
        static const char ctx[] = "u:object_r:kernel:s0";
        aarch64_asm_set_x_cstr_ptr(a, x0, ctx);

        KModErr err = KModErr::ERR_MODULE_ASM;
        kernel_module::export_symbol::security_secctx_to_secid(a, err, x0, strlen(ctx), result_sid_buf_kaddr);
        RETURN_FALSE_IF_ERROR(err);
        out_result_reg = x0;
        return true;
    }, result));
    printf("security_secctx_to_secid output result: %p\n", (void*)result);

    uint32_t result_sid = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(result_sid_buf_kaddr, &result_sid, sizeof(result_sid)));
    printf("security_secctx_to_secid result_sid: %d\n", result_sid);
    return KModErr::OK;
}