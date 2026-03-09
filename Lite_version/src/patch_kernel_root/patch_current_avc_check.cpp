#include "patch_current_avc_check.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchCurrentAvcCheck::PatchCurrentAvcCheck(const PatchBase& patch_base) : PatchBase(patch_base) {}

PatchCurrentAvcCheck::~PatchCurrentAvcCheck() {}

size_t PatchCurrentAvcCheck::patch_current_avc_check_bl_func(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int atomic_usage_len = get_cred_atomic_usage_len();
	int cred_euid_start_pos = get_cred_euid_offset();
	int uid_region_len = get_cred_uid_region_len();
	int securebits_padding = get_cred_securebits_padding();
	int securebits_len = 4 + securebits_padding;
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_cap_cnt();

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_end = a->newLabel();
	Label label_allow = a->newLabel();
	Label label_cycle_cap = a->newLabel();

	a->mov(x10, xzr);
	emit_get_current(a, x11);
	a->ldr(x11, ptr(x11, task_struct_cred_offset));
	a->ldr(w12, ptr(x11, cred_euid_start_pos));
	a->cbnz(w12, label_end);
	a->add(x11, x11, Imm(atomic_usage_len + uid_region_len));
	a->ldr(w13, ptr(x11).post(securebits_len));
	a->cbnz(w13, label_end);
	a->mov(x12, Imm(cap_ability_max));
	a->mov(x13, Imm(cap_cnt));
	a->bind(label_cycle_cap);
	a->ldr(x14, ptr(x11).post(8));
	a->cmp(x14, x12);
	a->b(CondCode::kLO, label_end);
	a->subs(x13, x13, Imm(1));
	a->b(CondCode::kNE, label_cycle_cap);
	a->bind(label_allow);
	a->mov(x10, Imm(1));
	a->bind(label_end);
	a->ret(x30);
	std::cout << print_aarch64_asm(a) << std::endl;
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_current_avc_check_bl_func failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	return shellcode_size;
}
