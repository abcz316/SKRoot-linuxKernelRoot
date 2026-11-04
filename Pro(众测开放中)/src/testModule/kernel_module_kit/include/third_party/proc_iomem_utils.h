#pragma once
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <string>

#ifndef SECTION_SIZE_BITS
#define SECTION_SIZE_BITS 30
#endif

#ifndef ARM64_MEMSTART_ALIGN
#define ARM64_MEMSTART_ALIGN (1UL << SECTION_SIZE_BITS)
#endif

static_assert(SECTION_SIZE_BITS == 30, "This helper requires 1 GiB alignment");
static_assert(ARM64_MEMSTART_ALIGN == (1ULL << 30), "ARM64_MEMSTART_ALIGN must be 1 GiB");

namespace proc_iomem_utils {

// 取所有 System RAM 区间的最低起点，再向下按 1 GiB 对齐。
// 注意：结果是按该规则推算的候选值，不保证等于内核运行时 PHYS_OFFSET。
// 返回 true 表示计算成功；失败时 out_phys_offset 为 0。
// iomem_path 默认读取 /proc/iomem，也可指定文本文件用于调试。
inline bool get_phys_offset_from_iomem(uint64_t& out_phys_offset, const char* iomem_path = "/proc/iomem") {
    out_phys_offset = 0;
    if (!iomem_path) return false;

    std::ifstream file(iomem_path);
    if (!file.is_open()) return false;

    uint64_t lowest_start = (std::numeric_limits<uint64_t>::max)();
    bool found = false;
    std::string line;
    while (std::getline(file, line)) {
        unsigned long long start = 0, end = 0;
        int name_pos = 0;
        if (std::sscanf(line.c_str(), " %llx-%llx : %n", &start, &end, &name_pos) != 2 || name_pos <= 0)
            continue;

        std::string name = line.substr(static_cast<std::size_t>(name_pos));
        const auto last = name.find_last_not_of(" \t\r");
        if (last == std::string::npos) continue;
        name.erase(last + 1);
        if (name != "System RAM") continue;

        // 00000000-00000000 常见于地址被隐藏；不将其作为有效地址。
        if (start > end || (start == 0 && end == 0)) return false;
        if (start < lowest_start) lowest_start = static_cast<uint64_t>(start);
        found = true;
    }

    if (file.bad() || !file.eof() || !found) return false;

    // 先转换为 64 位再取反，避免 32 位编译环境截断高位地址。
    out_phys_offset = lowest_start & ~(static_cast<uint64_t>(ARM64_MEMSTART_ALIGN) - 1);
    return true;
}

} // namespace proc_iomem_utils
