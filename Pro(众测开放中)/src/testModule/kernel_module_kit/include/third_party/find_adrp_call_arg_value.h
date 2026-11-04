#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>
#include <vector>
#include <capstone/capstone.h>

namespace a64_find_adrp_call_arg_value {

struct insn_info {
    size_t file_offset = 0;
    arm64_insn id = ARM64_INS_INVALID;
    bool is_adrp = false;
    uint8_t adrp_rd = 0;
    int64_t adrp_page_delta = 0;
    bool is_add_x_imm = false;
    uint8_t add_rd = 0;
    uint8_t add_rn = 0;
    uint64_t add_imm = 0;
    bool writes_target_reg = false;
    bool write_access_known = true;
};

static inline uint32_t read_u32_le(const std::vector<char>& file_buf, size_t offset) {
    const auto* p = reinterpret_cast<const uint8_t*>(file_buf.data() + offset);
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static inline bool is_target_call_insn(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x94000000u;
}

static inline int64_t sign_extend_21(uint32_t value) {
    value &= 0x1FFFFFu;
    return (value & 0x100000u) ? static_cast<int64_t>(value) - 0x200000LL
                               : static_cast<int64_t>(value);
}

static inline bool decode_adrp(uint32_t insn, uint8_t& result_rd, int64_t& result_page_delta) {
    if ((insn & 0x9F000000u) != 0x90000000u) return false;

    result_rd = static_cast<uint8_t>(insn & 0x1Fu);
    const uint32_t immlo = (insn >> 29) & 0x3u;
    const uint32_t immhi = (insn >> 5) & 0x7FFFFu;
    const uint32_t imm21 = (immhi << 2) | immlo;
    result_page_delta = sign_extend_21(imm21) * 0x1000LL;
    return true;
}

// 只识别 64 位 ADD Xd, Xn, #imm{, LSL #12}，不把 ADDS/SUB 当成 ADD。
static inline bool decode_add_x_imm(uint32_t insn, uint8_t& result_rd,
                                    uint8_t& result_rn, uint64_t& result_imm) {
    if ((insn & 0xFF000000u) != 0x91000000u) return false;

    result_rd = static_cast<uint8_t>(insn & 0x1Fu);
    result_rn = static_cast<uint8_t>((insn >> 5) & 0x1Fu);

    const uint64_t imm12 = (insn >> 10) & 0xFFFu;
    const uint32_t shift = (insn >> 22) & 0x1u;
    result_imm = imm12 << (shift ? 12 : 0);
    return true;
}

static inline bool is_control_flow_insn(arm64_insn id) {
    switch (id) {
    case ARM64_INS_B:
    case ARM64_INS_BL:
    case ARM64_INS_BR:
    case ARM64_INS_BLR:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
    case ARM64_INS_RET:
        return true;
    default:
        return false;
    }
}

static inline bool get_x_reg_num(uint32_t reg, int& result_x_reg_num) {
    static constexpr uint32_t x_regs[] = {
        ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3,
        ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7,
        ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11,
        ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X14, ARM64_REG_X15,
        ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23,
        ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27,
        ARM64_REG_X28, ARM64_REG_X29, ARM64_REG_X30
    };

    for (int i = 0; i < 31; ++i) {
        if (reg == x_regs[i]) {
            result_x_reg_num = i;
            return true;
        }
    }
    return false;
}

static inline bool is_target_reg(unsigned int reg, int x_reg_num) {
    if (x_reg_num < 0 || x_reg_num > 30) return false;

    static constexpr unsigned int x_regs[] = {
        ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3,
        ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7,
        ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11,
        ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X14, ARM64_REG_X15,
        ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23,
        ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27,
        ARM64_REG_X28, ARM64_REG_X29, ARM64_REG_X30
    };
    static constexpr unsigned int w_regs[] = {
        ARM64_REG_W0, ARM64_REG_W1, ARM64_REG_W2, ARM64_REG_W3,
        ARM64_REG_W4, ARM64_REG_W5, ARM64_REG_W6, ARM64_REG_W7,
        ARM64_REG_W8, ARM64_REG_W9, ARM64_REG_W10, ARM64_REG_W11,
        ARM64_REG_W12, ARM64_REG_W13, ARM64_REG_W14, ARM64_REG_W15,
        ARM64_REG_W16, ARM64_REG_W17, ARM64_REG_W18, ARM64_REG_W19,
        ARM64_REG_W20, ARM64_REG_W21, ARM64_REG_W22, ARM64_REG_W23,
        ARM64_REG_W24, ARM64_REG_W25, ARM64_REG_W26, ARM64_REG_W27,
        ARM64_REG_W28, ARM64_REG_W29, ARM64_REG_W30
    };
    return reg == x_regs[x_reg_num] || reg == w_regs[x_reg_num];
}

static inline bool get_writes_target_reg(csh handle, const cs_insn* insn,
                                         int x_reg_num, bool& result_writes) {
    result_writes = false;
    if (!insn || !insn->detail) return false;

    cs_regs regs_read = {};
    cs_regs regs_write = {};
    uint8_t regs_read_count = 0;
    uint8_t regs_write_count = 0;

    if (cs_regs_access(handle, insn, regs_read, &regs_read_count,
                       regs_write, &regs_write_count) != CS_ERR_OK) {
        return false;
    }

    for (uint8_t i = 0; i < regs_write_count; ++i) {
        if (is_target_reg(regs_write[i], x_reg_num)) {
            result_writes = true;
            break;
        }
    }
    return true;
}

/***************************************************************************
 * 还原调用指令前指定寄存器的 ADRP 地址值
 * 参数:
 *   file_buf       指令所在文件缓冲区
 *   search_start   向前回溯搜索的最早文件偏移（包含该位置）。
 *   bl_offset      BL 指令的文件偏移
 *   reg            目标寄存器，例如 ARM64_REG_X0、ARM64_REG_X1
 *   start_vaddr    file_buf[search_start] 对应的运行时虚拟地址
 *   result_value      输出：调用指令执行前目标寄存器的值
 * 返回: true 表示成功还原；false 表示无法可靠还原
 **************************************************************************/
static inline bool find_adrp_call_arg_value(const std::vector<char>& file_buf,
                                     size_t search_start,
                                     size_t bl_offset,
                                     uint32_t reg,
                                     uint64_t start_vaddr,
                                     uint64_t& result_value) {
    result_value = 0;

    int x_reg_num = -1;
    if (!get_x_reg_num(reg, x_reg_num)) return false;
    if (search_start >= file_buf.size() || bl_offset < search_start) return false;
    if (bl_offset > file_buf.size() || file_buf.size() - bl_offset < sizeof(uint32_t)) return false;
    if ((search_start & 3u) != 0 || (bl_offset & 3u) != 0) return false;
    if (((bl_offset - search_start) & 3u) != 0) return false;
    if (!is_target_call_insn(read_u32_le(file_buf, bl_offset))) return false;

    const size_t scan_end = bl_offset + sizeof(uint32_t);
    const uint64_t code_vaddr = start_vaddr;
    if (code_vaddr > std::numeric_limits<uint64_t>::max() - (scan_end - search_start)) return false;

    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return false;
    }

    std::vector<insn_info> instructions;
    instructions.reserve((scan_end - search_start) / sizeof(uint32_t));

    const uint8_t* code = reinterpret_cast<const uint8_t*>(file_buf.data()) + search_start;
    size_t remaining_size = scan_end - search_start;
    uint64_t address = code_vaddr;
    size_t cur_offset = search_start;
    bool decode_ok = true;

    while (remaining_size) {
        const size_t before = remaining_size;
        if (!cs_disasm_iter(handle, &code, &remaining_size, &address, insn)) {
            decode_ok = false;
            break;
        }

        const size_t insn_size = before - remaining_size;
        if (insn_size != sizeof(uint32_t) || !insn->detail) {
            decode_ok = false;
            break;
        }

        insn_info info;
        info.file_offset = cur_offset;
        info.id = static_cast<arm64_insn>(insn->id);

        const uint32_t word = read_u32_le(file_buf, cur_offset);
        info.is_adrp = decode_adrp(word, info.adrp_rd, info.adrp_page_delta);

        info.is_add_x_imm = decode_add_x_imm(word, info.add_rd, info.add_rn, info.add_imm);

        if (cur_offset != bl_offset) {
            info.write_access_known = get_writes_target_reg(handle, insn, x_reg_num,
                                                            info.writes_target_reg);
        }

        instructions.push_back(info);
        cur_offset += insn_size;
    }

    cs_free(insn, 1);
    cs_close(&handle);

    if (!decode_ok || cur_offset != scan_end || instructions.empty()) return false;
    if (instructions.back().file_offset != bl_offset || instructions.back().id != ARM64_INS_BL) return false;

    const size_t target_index = instructions.size() - 1;
    size_t adrp_index = static_cast<size_t>(-1);

    // 从目标调用指令向前找最近一条 ADRP Xn。
    for (size_t i = target_index; i > 0; --i) {
        const auto& item = instructions[i - 1];
        if (item.is_adrp && item.adrp_rd == static_cast<uint8_t>(x_reg_num)) {
            adrp_index = i - 1;
            break;
        }
    }
    if (adrp_index == static_cast<size_t>(-1)) return false;

    const auto& adrp_item = instructions[adrp_index];
    const uint64_t adrp_pc = code_vaddr + (adrp_item.file_offset - search_start);
    uint64_t value = (adrp_pc & ~0xFFFULL) +
                     static_cast<uint64_t>(adrp_item.adrp_page_delta);

    // 从 ADRP 后面顺序扫描到目标调用指令，累计 ADD Xn, Xn, #imm。
    for (size_t i = adrp_index + 1; i < target_index; ++i) {
        const auto& item = instructions[i];

        // 线性扫描不跟踪分支目标；遇到控制流指令时，无法保证这些 ADD 一定会执行。
        if (is_control_flow_insn(item.id)) return false;

        if (item.is_add_x_imm &&
            item.add_rd == static_cast<uint8_t>(x_reg_num) &&
            item.add_rn == static_cast<uint8_t>(x_reg_num)) {
            value += item.add_imm;
            continue;
        }

        // 无法判断寄存器读写，或者其他指令改写了目标寄存器，原 ADRP 值就不再可靠。
        if (!item.write_access_known || item.writes_target_reg) return false;
    }

    result_value = value;
    return true;
}


} // namespace a64_find_adrp_call_arg_value
