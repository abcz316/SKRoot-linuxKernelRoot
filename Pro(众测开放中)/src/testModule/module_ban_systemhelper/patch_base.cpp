#include "patch_base.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

namespace {
// AndroidUID = AndroidUserId x 100000 + appId
// uint32_t appId = UID % 100000
constexpr uint32_t MAX_ANDROID_APPID = 100000;

// 计算无符号除法的硬件魔法数：(2^44 / divisor) 向上取整
constexpr uint32_t calc_uid_mod_magic(uint32_t divisor) {
	return static_cast<uint32_t>(((1ULL << 44) + divisor - 1) / divisor);
}
static_assert(calc_uid_mod_magic(MAX_ANDROID_APPID) == 0x0A7C5AC5);
}

PatchBase::PatchBase(uint32_t cred_offset, uint32_t euid_offset)
	: m_cred_offset(cred_offset), m_euid_offset(euid_offset) {}

PatchBase::PatchBase(const PatchBase& other)
	: m_cred_offset(other.m_cred_offset), m_euid_offset(other.m_euid_offset) {}

PatchBase::~PatchBase() {}

void PatchBase::emit_get_euid_to_w11(Assembler* a, Label on_error) {
	Label local_end;
	if (!on_error.isValid()) {
		local_end = a->newLabel();
		on_error = local_end;
	}
	kernel_module::export_symbol::get_current(a, x11, on_error);
	a->ldr(x11, ptr(x11, m_cred_offset));
	a->ldr(w11, ptr(x11, m_euid_offset)); // 读euid就够了
	if (local_end.isValid()) {
		a->bind(local_end);
	}
}

void PatchBase::emit_uid_to_appid(Assembler* a, GpW w_uid, GpW w_tmp1, GpW w_tmp2, GpW w_appid) {
	Label label_uid_lt_100000 = a->newLabel();
	Label label_appid_ready = a->newLabel();

	// 判断 UID 是否小于 100000
	aarch64_asm_mov_w(a, w_tmp1, MAX_ANDROID_APPID);
	a->cmp(w_uid, w_tmp1);
	a->b(CondCode::kLO, label_uid_lt_100000);

	// UID >= 100000，计算 appId = UID % 100000
	{
		// appId = uid % 100000，w_uid = uid
		// 1. UID 先右移5位
		a->lsr(w_tmp2, w_uid, Imm(5));
		// 2. 加载魔法数
		aarch64_asm_mov_w(a, w_tmp1, calc_uid_mod_magic(MAX_ANDROID_APPID));
		// 3. 32位无符号乘法，得到64位结果
		a->umull(x(w_tmp2.id()), w_tmp2, w_tmp1);
		// 4. 右移39位得到商
		a->lsr(x(w_tmp2.id()), x(w_tmp2.id()), Imm(39)); // 此时 w_tmp2 已经是 userId，w_tmp2 = uid / 100000;
		// 5. 计算余数 appId
		aarch64_asm_mov_w(a, w_tmp1, MAX_ANDROID_APPID);
		a->msub(w_appid, w_tmp2, w_tmp1, w_uid); // w_appid = w_uid - w_tmp2 * w_tmp1; w_appid = uid - userId * 100000;
		a->b(label_appid_ready);
	}
	// UID < 100000，直接使用 UID 作为 appId
	a->bind(label_uid_lt_100000);
	a->mov(w_appid, w_uid);

	a->bind(label_appid_ready);
}

void PatchBase::emit_match_current_appid_to_x10(Assembler* a, uint32_t target_uid) {
	Label label_end = a->newLabel();

	a->mov(x10, Imm(0));

	// 读当前任务 euid 到 w11。
	emit_get_euid_to_w11(a, label_end);

	// 解析 appId = euid % 100000，w11 = euid，w12/w13 作中转，结果保留在 w14。
	emit_uid_to_appid(a, w11, w12, w13, w14);

	// 与目标 appId（忽略 userId）比较。
	aarch64_asm_mov_w(a, w13, target_uid % MAX_ANDROID_APPID);
	a->cmp(w14, w13);
	a->b(CondCode::kNE, label_end);

	a->mov(x10, Imm(1));
	a->bind(label_end);
}

KModErr PatchBase::patch_kernel_before_hook(uint64_t kaddr, const Assembler* a) {
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::install_kernel_function_before_hook(kaddr, bytes));
	return KModErr::OK;
}

KModErr PatchBase::patch_kernel_after_hook(uint64_t kaddr, const Assembler* a) {
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::install_kernel_function_after_hook(kaddr, bytes));
	return KModErr::OK;
}
