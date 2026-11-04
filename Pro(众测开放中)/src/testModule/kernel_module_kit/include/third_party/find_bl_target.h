#pragma once
#include <cstdint>
#include <cstddef>
#include <limits>
#include <vector>
#include <capstone/capstone.h>

namespace a64_find_bl_target {

    /***************************************************************************
     * 在指定文件范围内查找跳转到目标地址的 AArch64 BL 指令
     *
     * 参数:
     *   file_buf       内核二进制文件数据
     *   start          文件搜索起始偏移
     *   size           文件搜索范围大小
     *   start_vaddr    file_buf[start] 对应的运行时虚拟地址
     *   target         目标运行时虚拟地址
     *   out_offset     输出：命中 BL 指令在 file_buf 中的绝对文件偏移
     *
     * 返回:
     *   true  表示找到匹配的 BL 指令
     *   false 表示未找到或发生错误
     *
     * 注意:
     *   1. start_vaddr 和 target 必须处于相同的运行时地址空间。
     *   2. start_vaddr 必须满足 ARM64 指令 4 字节对齐要求。
     *   3. 默认搜索范围内的文件偏移与运行时虚拟地址呈线性映射。
     *      如果跨越不同 ELF PT_LOAD 段，应分别搜索。
     ***************************************************************************/
    static inline bool find_bl_target(const std::vector<char>& file_buf, size_t start, size_t size, uint64_t start_vaddr, uint64_t target, size_t& out_offset) {
        out_offset = 0;
        if (start > file_buf.size() || size > file_buf.size() - start || size < sizeof(uint32_t)) return false;
        if (start_vaddr & 3) return false;
        if (start_vaddr > std::numeric_limits<uint64_t>::max() - (size - sizeof(uint32_t))) return false;
        const size_t end = start + size;
        csh handle = 0;
        if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return false;
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
            cs_close(&handle);
            return false;
        }
        cs_insn* insn = cs_malloc(handle);
        if (!insn) {
            cs_close(&handle);
            return false;
        }
        bool found = false;
        for (size_t cur = start; cur <= end - sizeof(uint32_t); cur += sizeof(uint32_t)) {

            const uint8_t* code = reinterpret_cast<const uint8_t*>(file_buf.data() + cur);
            size_t code_size = sizeof(uint32_t);

            // 当前指令对应的运行时虚拟地址
            uint64_t address = start_vaddr + (cur - start);

            if (!cs_disasm_iter(handle, &code, &code_size, &address, insn)) continue;

            if (insn->id != ARM64_INS_BL || !insn->detail) continue;

            const cs_arm64& arm64 = insn->detail->arm64;

            if (arm64.op_count < 1 || arm64.operands[0].type != ARM64_OP_IMM) continue;

            // 比较 BL 指令计算出的目标运行时虚拟地址
            if (static_cast<uint64_t>(arm64.operands[0].imm) != target) continue;

            out_offset = cur;
            found = true;
            break;
        }
        cs_free(insn, 1);
        cs_close(&handle);
        return found;
    }

} // namespace a64_find_bl_target