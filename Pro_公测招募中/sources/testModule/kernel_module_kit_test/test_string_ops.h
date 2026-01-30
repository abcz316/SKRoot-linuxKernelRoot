#include "kernel_module_kit_test.h"
#include <iostream>
#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

KModErr Test_kstrlen() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    kernel_module::string_ops::kstrlen(a, x1);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrlen result: %s\n", result == 9 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrnlen1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);

    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    a->mov(x2, Imm(100));
    kernel_module::string_ops::kstrnlen(a, x1, x2);

    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrnlen1 (maxlen>len) result: %s\n", result == 9 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrnlen2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);

    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    a->mov(x2, Imm(9));
    kernel_module::string_ops::kstrnlen(a, x1, x2);

    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrnlen2 (maxlen==len) result: %s\n", result == 9 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrnlen3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);

    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    a->mov(x2, Imm(5));
    kernel_module::string_ops::kstrnlen(a, x1, x2);

    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrnlen3 (maxlen<len) result: %s\n", result == 5 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrcmp1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123456789");
    kernel_module::string_ops::kstrcmp(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrcmp1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrcmp2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "987654321");
    kernel_module::string_ops::kstrcmp(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrcmp2 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrcmp3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "666888");
    kernel_module::string_ops::kstrcmp(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrcmp3 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123456789");
    a->mov(x3, Imm(100));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrncmp1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "987654321");
    a->mov(x3, Imm(100));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrncmp2 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}


KModErr Test_kstrncmp3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "666888");
    a->mov(x3, Imm(100));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrncmp3 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp4() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "1234aaabbbcccddd");
    a->mov(x3, Imm(4));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrncmp4 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp5() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123454321");
    a->mov(x3, Imm(9));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kstrncmp5 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp6() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "678456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "678888");
    a->mov(x3, Imm(3));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstrncmp6 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncmp7() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123888");
    a->mov(x3, Imm(3));
    kernel_module::string_ops::kstrncmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstrncmp7 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrcpy() {
    uint32_t test_data[2] = {0x11223344, 0x55667788};

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(sizeof(test_data), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, &test_data, sizeof(test_data)));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "abc");
    kernel_module::string_ops::kstrcpy(a, x0, x1);
    kernel_module::arm64_module_asm_func_end(a);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(sizeof(test_data));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kstrcpy result: %s\n", after_str == "abc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncpy() {
    std::vector<uint8_t> init(16, 0xCC);
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "abc");
    aarch64_asm_mov_x(a, x2, 8);
    kernel_module::string_ops::kstrncpy(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    // 读回验证
    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));

    const uint8_t expected_prefix[8] = {
        (uint8_t)'a', (uint8_t)'b', (uint8_t)'c', 0, 0, 0, 0, 0
    };

    bool ok_prefix = (0 == memcmp(buf.data(), expected_prefix, sizeof(expected_prefix)));
    bool ok_tail   = (buf.size() > 8 && buf[8] == 0xCC); // n(8) 之后不应被改写

    printf("kstrncpy result: %s\n", (ok_prefix && ok_tail) ? "ok" : "failed");

    // 失败时打印前 16 字节，方便看写入形态
    if (!(ok_prefix && ok_tail)) {
        printf("dump: ");
        for (size_t i = 0; i < buf.size(); ++i) {
            printf("%02X ", buf[i]);
        }
        printf("\n");
    }
    return KModErr::OK;
}

KModErr Test_kstrcat1() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "DEF");
    kernel_module::string_ops::kstrcat(a, x0, x1);
    kernel_module::arm64_module_asm_func_end(a);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    bool ok = (after == "abcDEF") && (buf[7] == 0xCC); // '\0' 后面的哨兵不应被改写
    printf("kstrcat1 result: %s\n", ok ? "ok" : "failed");
    if (!ok) printf("after='%s'\n", after.c_str());
    return KModErr::OK;
}

KModErr Test_kstrcat2() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 0; // dst = ""

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "XYZ");
    kernel_module::string_ops::kstrcat(a, x0, x1);
    kernel_module::arm64_module_asm_func_end(a);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    bool ok = (after == "XYZ") && (buf[4] == 0xCC);
    printf("kstrcat2 result: %s\n", ok ? "ok" : "failed");
    if (!ok) printf("after='%s'\n", after.c_str());
    return KModErr::OK;
}

KModErr Test_kstrcat3() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);          // dst
    aarch64_asm_set_x_cstr_ptr(a, x1, "");    // src = ""
    kernel_module::string_ops::kstrcat(a, x0, x1);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    bool ok = (after == "abc") && (result == addr) && (buf[4] == 0xCC);
    printf("kstrcat3 result: %s\n", ok ? "ok" : "failed");
    if (!ok) printf("after='%s' ret=0x%llx addr=0x%llx\n",
                    after.c_str(), (unsigned long long)result, (unsigned long long)addr);
    return KModErr::OK;
}

KModErr Test_kstrcat4() {
    std::vector<uint8_t> init(32, 0xCC);

    // dst = "12345678901234567890" (长度 20) + '\0'
    const char* base = "12345678901234567890";
    memcpy(init.data(), base, 20);
    init[20] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);          // dst
    aarch64_asm_set_x_cstr_ptr(a, x1, "Z");   // src = "Z"
    kernel_module::string_ops::kstrcat(a, x0, x1);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    // 期望：长度 21，'\0' 在 index 21；index 22/23 仍为 0xCC
    bool ok = (after == "12345678901234567890Z") &&
              (result == addr) &&
              (buf[22] == 0xCC) && (buf[23] == 0xCC);

    printf("kstrcat4 result: %s\n", ok ? "ok" : "failed");
    if (!ok) {
        printf("after='%s' ret=0x%llx addr=0x%llx\n",
               after.c_str(), (unsigned long long)result, (unsigned long long)addr);
        printf("dump: ");
        for (size_t i = 0; i < buf.size(); ++i) printf("%02X ", buf[i]);
        printf("\n");
    }
    return KModErr::OK;
}

KModErr Test_kstrncat1() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);          // dst
    aarch64_asm_set_x_cstr_ptr(a, x1, "DEF");// src
    aarch64_asm_mov_x(a, x2, 2);             // n=2
    kernel_module::string_ops::kstrncat(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    // "abcDE\0" 长度 5，'\0' 在 index 5；index 6 仍应是 0xCC
    bool ok = (after == "abcDE") && (result == addr) && (buf[6] == 0xCC);
    printf("kstrncat1 result: %s\n", ok ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncat2() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "DEF");
    aarch64_asm_mov_x(a, x2, 8);             // n=8
    kernel_module::string_ops::kstrncat(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    // "abcDEF\0" => '\0' 在 index 6；index 7 仍应是 0xCC
    bool ok = (after == "abcDEF") && (result == addr) && (buf[7] == 0xCC);
    printf("kstrncat2 result: %s\n", ok ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncat3() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "DEF");
    aarch64_asm_mov_x(a, x2, 0);             // n=0
    kernel_module::string_ops::kstrncat(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);

    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    bool ok = (after == "abc") && (result == addr) && (buf[4] == 0xCC);
    printf("kstrncat3 result: %s\n", ok ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncat4() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 'a'; init[1] = 'b'; init[2] = 'c'; init[3] = 0;

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "");   // src=""
    aarch64_asm_mov_x(a, x2, 5);
    kernel_module::string_ops::kstrncat(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    bool ok = (after == "abc") && (result == addr) && (buf[4] == 0xCC);
    printf("kstrncat4 result: %s\n", ok ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrncat5() {
    std::vector<uint8_t> init(32, 0xCC);
    init[0] = 0; // dst=""

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(init.size(), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, init.data(), init.size()));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "XYZ123");
    aarch64_asm_mov_x(a, x2, 3);             // n=3
    kernel_module::string_ops::kstrncat(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    std::vector<uint8_t> buf(init.size());
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after(reinterpret_cast<const char*>(buf.data()));

    // "XYZ\0" => '\0' 在 index 3；index 4 仍应是 0xCC
    bool ok = (after == "XYZ") && (result == addr) && (buf[4] == 0xCC);
    printf("kstrncat5 result: %s\n", ok ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrstr1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    aarch64_asm_set_x_cstr_ptr(a, x2, "vvvccc");
    kernel_module::string_ops::kstrstr(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstrstr1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrstr2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "12345");
    aarch64_asm_set_x_cstr_ptr(a, x2, "aaabbbccc");
    kernel_module::string_ops::kstrstr(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstrstr2 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrstr3() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    aarch64_asm_set_x_cstr_ptr(a, x2, "789aaa");
    kernel_module::string_ops::kstrstr(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("789aaabbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kstrstr3 result: %s\n", after_str == "789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrchr1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('v'));
    kernel_module::string_ops::kstrchr(a, x1, w2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstrchr1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrchr2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(w2, Imm('7'));
    kernel_module::string_ops::kstrchr(a, x1, w2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("789aaabbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kstrchr2 result: %s\n", after_str == "789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrrchr1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('v'));
    kernel_module::string_ops::kstrrchr(a, x1, w2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    printf("kstrrchr1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrrchr2() {
    const char* s = "123456789aaabbbccc";
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, s, strlen(s) + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(w2, Imm('a'));
    kernel_module::string_ops::kstrrchr(a, x1, w2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    if (result == 0) {
        printf("kstrrchr2 result: failed (null)\n");
        return KModErr::OK;
    }
    std::vector<uint8_t> buf(sizeof("abbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(result, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));

    printf("kstrrchr2 result: %s\n", after_str == "abbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstrrchr3() {
    const char* s = "123456789aaabbbccc";

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, s, strlen(s) + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(w2, Imm(0));
    kernel_module::string_ops::kstrrchr(a, x1, w2);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    uint64_t expect = addr + (uint64_t)strlen(s);
    printf("kstrrchr3 result: %s\n", result == expect ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemset1() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    a->mov(w1, Imm('k'));
    aarch64_asm_mov_x(a, x2, 5);
    kernel_module::string_ops::kmemset(a, x0, w1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("kkkkk6789aaabbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kmemset1 result: %s\n", after_str == "kkkkk6789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemset2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_mov_x(a, x1, 5);
    kernel_module::string_ops::kmemset(a, x0, 'k', x1);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    addr = result;
    std::vector<uint8_t> buf(sizeof("kkkkk6789aaabbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kmemset2 result: %s\n", after_str == "kkkkk6789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemcmp1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "987654321");
    a->mov(x3, Imm(strlen("123456789")));
    kernel_module::string_ops::kmemcmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemcmp1 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemcmp2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "12345");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123456789");
    a->mov(x3, Imm(strlen("123456789")));
    kernel_module::string_ops::kmemcmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemcmp2 result: %s\n", result != 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemcmp3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123456789");
    a->mov(x3, Imm(strlen("123456789")));
    kernel_module::string_ops::kmemcmp(a, x1, x2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemcmp3 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemcpy() {
    uint32_t test_data[2] = {0x11223344, 0x55667788};

    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(sizeof(test_data), addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, &test_data, sizeof(test_data)));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x0, addr);
    aarch64_asm_set_x_cstr_ptr(a, x1, "aabbcc");
    a->mov(x2, Imm(strlen("aabbcc") + 1));
    kernel_module::string_ops::kmemcpy(a, x0, x1, x2);
    kernel_module::arm64_module_asm_func_end(a);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    std::vector<uint8_t> buf(sizeof(test_data));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kmemcpy result: %s\n", after_str == "aabbcc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(x2, Imm(sizeof("123456789aaabbbccc") - 1));
    aarch64_asm_set_x_cstr_ptr(a, x3, "vvvccc");
    a->mov(x4, Imm(sizeof("vvvccc") - 1));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    printf("kmemmem1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", sizeof("123456789aaabbbccc")));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof("123456789aaabbbccc") - 1));
    aarch64_asm_set_x_cstr_ptr(a, x3, "789aaa");
    a->mov(x4, Imm(sizeof("789aaa") - 1));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));

    addr = result;
    std::vector<uint8_t> buf(sizeof("789aaabbbccc") - 1);
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    buf.push_back(0);
    std::string s(reinterpret_cast<const char*>(buf.data()));
    printf("kmemmem2 result: %s\n", s == "789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem3() {
    //单元测试：kmemmem3 - 命中（起始位置），返回值应等于 buf 的地址
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "hello-world", sizeof("hello-world")));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof("hello-world") - 1));
    aarch64_asm_set_x_cstr_ptr(a, x3, "hello");
    a->mov(x4, Imm(sizeof("hello") - 1));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("hello") - 1);
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    buf.push_back(0);
    std::string s(reinterpret_cast<const char*>(buf.data()));
    printf("kmemmem3 result: %s\n", s == "hello" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem4() {
    // 单元测试：kmemmem4 - 空模式串（needle_n == 0），应返回 buf
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", sizeof("123456789aaabbbccc")));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof("123456789aaabbbccc") - 1));
    aarch64_asm_set_x_cstr_ptr(a, x3, "");
    a->mov(x4, Imm(0));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);

    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    addr = result;
    std::vector<uint8_t> buf(sizeof("123456789aaabbbccc") - 1);
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    buf.push_back(0);
    std::string s(reinterpret_cast<const char*>(buf.data()));
    printf("kmemmem4 result: %s\n", s == "123456789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem5() {

    char datas[] = {0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x61, 0x6c, 0x6c, 0x5f, 0x64, 0x65, 0x6d, 0x6f,
        0x00, 0x74, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x31, 0x00, 0x31, 0x37, 0x35, 0x36, 0x33, 0x39, 0x36, 0x36,
        0x36, 0x37, 0x00};
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, datas, sizeof(datas)));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof(datas)));
    std::vector<uint8_t> double_zero(2);
    aarch64_asm_set_x_data_ptr(a, x3, double_zero);
    a->mov(x4, Imm(2));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    uint64_t kaddr = result;
    printf("kmemmem5 result: %s\n", kaddr == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem6() {
    char datas[] = {0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x61, 0x6c, 0x6c, 0x5f, 0x64, 0x65, 0x6d, 0x6f,
        0x00, 0x74, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x31, 0x00, 0x31, 0x37, 0x35, 0x36, 0x33, 0x39, 0x36, 0x36,
        0x36, 0x00, 0x00};
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, datas, sizeof(datas)));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof(datas)));
    std::vector<uint8_t> double_zero(2);
    aarch64_asm_set_x_data_ptr(a, x3, double_zero);
    a->mov(x4, Imm(2));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    uint64_t correct_addr = addr + sizeof(datas) - 2;
    uint64_t kaddr = result;
    printf("kmemmem6 result: %s\n", kaddr == correct_addr ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemmem7() {
    char datas[] = {0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x61, 0x6c, 0x6c, 0x5f, 0x64, 0x65, 0x6d, 0x00,
        0x00, 0x74, 0x65, 0x73, 0x74, 0x4b, 0x65, 0x79, 0x31, 0x00, 0x31, 0x37, 0x35, 0x36, 0x33, 0x39, 0x36, 0x36,
        0x36, 0x00, 0x00};
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, datas, sizeof(datas)));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(x2, Imm(sizeof(datas)));
    std::vector<uint8_t> double_zero(2);
    aarch64_asm_set_x_data_ptr(a, x3, double_zero);
    a->mov(x4, Imm(2));
    kernel_module::string_ops::kmemmem(a, x1, x2, x3, x4);
    kernel_module::arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
	uint64_t correct_addr = addr + 14;
    uint64_t kaddr = result;
    printf("kmemmem7 result: %s\n", kaddr == correct_addr ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemchr1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('v'));
    a->mov(x3, Imm(sizeof("123456789aaabbbccc")));
    kernel_module::string_ops::kmemchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemchr1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemchr2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(w2, Imm('7'));
	a->mov(x3, Imm(sizeof("123456789aaabbbccc")));
    kernel_module::string_ops::kmemchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("789aaabbbccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kmemchr2 result: %s\n", after_str == "789aaabbbccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemchr3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('9'));
    a->mov(x3, Imm(8));
    kernel_module::string_ops::kmemchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemchr3 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemrchr1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('v'));
    a->mov(x3, Imm(sizeof("123456789aaabbbccc")));
    kernel_module::string_ops::kmemrchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemrchr1 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemrchr2() {
    uint64_t addr = 0;
    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(1024, addr));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(addr, "123456789aaabbbccc", strlen("123456789aaabbbccc") + 1));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_mov_x(a, x1, addr);
    a->mov(w2, Imm('b'));
	a->mov(x3, Imm(sizeof("123456789aaabbbccc")));
    kernel_module::string_ops::kmemrchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    

    addr = result;
    std::vector<uint8_t> buf(sizeof("bccc"));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(addr, buf.data(), buf.size()));
    std::string after_str(reinterpret_cast<const char*>(buf.data()));
    printf("kmemrchr2 result: %s\n", after_str == "bccc" ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kmemrchr3() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789aaabbbccc");
    a->mov(w2, Imm('9'));
    a->mov(x3, Imm(8));
    kernel_module::string_ops::kmemrchr(a, x1, w2, x3);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kmemrchr3 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}


KModErr Test_kstartswith1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123");
    kernel_module::string_ops::kstartswith(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstartswith1 result: %s\n", result == 1 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kstartswith2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "912345678");
    aarch64_asm_set_x_cstr_ptr(a, x2, "123");
    kernel_module::string_ops::kstartswith(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kstartswith2 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kendswith1() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789"); // str
    aarch64_asm_set_x_cstr_ptr(a, x2, "789");       // suffix (应当匹配)
    kernel_module::string_ops::kendswith(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kendswith1 result: %s\n", result == 1 ? "ok" : "failed");
    return KModErr::OK;
}

KModErr Test_kendswith2() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    a->mov(x0, Imm(123));
    aarch64_asm_set_x_cstr_ptr(a, x1, "123456789");
    aarch64_asm_set_x_cstr_ptr(a, x2, "6789x");
    kernel_module::string_ops::kendswith(a, x1, x2);
    kernel_module::arm64_module_asm_func_end(a, x0);
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t result = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    
    printf("kendswith2 result: %s\n", result == 0 ? "ok" : "failed");
    return KModErr::OK;
}
