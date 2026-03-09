#include "patch_base.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

struct cred_uid_info {
	uint32_t uid; /* real UID of the task */
	uint32_t gid; /* real GID of the task */
	uint32_t suid; /* saved UID of the task */
	uint32_t sgid; /* saved GID of the task */
	uint32_t euid; /* effective UID of the task */
	uint32_t egid; /* effective GID of the task */
	uint32_t fsuid; /* UID for VFS ops */
	uint32_t fsgid; /* GID for VFS ops */
};

PatchBase::PatchBase(const std::vector<char>& file_buf, size_t cred_uid_offset) : 
	m_file_buf(file_buf), m_kernel_ver_parser(file_buf), m_cred_uid_offset(cred_uid_offset) {}

PatchBase::PatchBase(const PatchBase& other)
	: m_file_buf(other.m_file_buf)
	, m_kernel_ver_parser(other.m_file_buf)
	, m_cred_uid_offset(other.m_cred_uid_offset)
{}

PatchBase::~PatchBase() {}

uint32_t PatchBase::skip_pac_bti_at_func_start(uint32_t addr) {
	uint32_t instr = *reinterpret_cast<const uint32_t*>(&m_file_buf[addr]);
	if (aarch64_insn_is_pac_or_bti(instr)) return addr + 4;
	return addr;
}

SymbolRegion PatchBase::skip_pac_bti_at_func_start(const SymbolRegion& symbol) {
	uint32_t skip = skip_pac_bti_at_func_start(symbol.offset) - symbol.offset;
	SymbolRegion new_sym = symbol;
	new_sym.consume(skip);
	return new_sym;
}

int PatchBase::get_cred_atomic_usage_len() {
	return m_cred_uid_offset;
}

int PatchBase::get_cred_uid_region_len() {
	return sizeof(cred_uid_info);
}

int PatchBase::get_cred_euid_offset() {
	return get_cred_atomic_usage_len() + offsetof(cred_uid_info, euid);
}

int PatchBase::get_cred_securebits_padding() {
	if (get_cred_atomic_usage_len() == 8) return 4;
	return 0;
}

uint64_t PatchBase::get_cap_ability_max() {
	uint64_t cap = 0x3FFFFFFFFF;
	if (m_kernel_ver_parser.is_kernel_version_less("5.8.0")) cap = 0x3FFFFFFFFF;
	else if (m_kernel_ver_parser.is_kernel_version_less("5.9.0")) cap = 0xFFFFFFFFFF;
	else cap = 0x1FFFFFFFFFF;
	return cap;
}

int PatchBase::get_cap_cnt() {
	int cnt = 0;
	if (m_kernel_ver_parser.is_kernel_version_less("4.3.0")) cnt = 4;
	else cnt = 5;
	return cnt;
}

size_t PatchBase::patch_jump(size_t patch_addr, size_t jump_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	aarch64_asm_b(a, (int32_t)(jump_addr - patch_addr));
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	vec_out_patch_bytes_data.push_back({ str_bytes, patch_addr });
	return bytes.size();
}

bool PatchBase::is_CONFIG_THREAD_INFO_IN_TASK() {
	return !m_kernel_ver_parser.is_kernel_version_less("4.4.207");
}

void PatchBase::emit_get_current(Assembler* a, GpX x) {
	struct thread_info {
		uint64_t flags;		/* low level flags */
		uint64_t addr_limit;	/* address limit */
	};
	Label label_error = a->newLabel();
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	a->mrs(x, sp_el0_id);
	if (!is_CONFIG_THREAD_INFO_IN_TASK()) {
		a->cbz(x, label_error);
		a->and_(x, x, Imm((uint64_t)~(0x4000 - 1)));
		a->ldr(x, ptr(x, sizeof(thread_info)));
		a->bind(label_error);
	}
}

void PatchBase::emit_safe_bl(Assembler* a, size_t func_base_addr, size_t target) {
	RegProtectGuard g1(a, x29, x30);
	size_t bl_addr = func_base_addr + a->offset();
	int64_t diff = (int64_t)target - (int64_t)bl_addr;
	aarch64_asm_bl_raw(a, (int32_t)diff);
}

void PatchBase::emit_ret_by_entry_insn(Assembler* a, uint32_t entry_insn) {
    if (aarch64_insn_is_paciaz(entry_insn)) {
        aarch64_asm_autiaz(a);
        a->ret(x30);
    } else if (aarch64_insn_is_paciasp(entry_insn)) {
        aarch64_asm_retaa(a);
    } else if (aarch64_insn_is_pacibz(entry_insn)) {
        aarch64_asm_autibz(a);
        a->ret(x30);
    } else if (aarch64_insn_is_pacibsp(entry_insn)) {
        aarch64_asm_retab(a);
    } else {
        a->ret(x30);
    }
}

std::vector<size_t> PatchBase::find_all_aarch64_ret_offsets(size_t offset, size_t size) {
	std::vector<size_t> v_ret_addr;
	std::string mode;
	for (size_t i = offset; i < offset + size; i += 4) {
		uint32_t instr = *reinterpret_cast<const uint32_t*>(&m_file_buf[i]);
		std::string cur;
		if (aarch64_insn_is_ret(instr)) cur = "ret";
		else if (aarch64_insn_is_retaa(instr)) cur = "retaa";
		else if (aarch64_insn_is_retab(instr)) cur = "retab";
		if (cur.empty()) continue;
		if (mode.empty()) mode = cur;
		else if (mode != cur) {
			printf("Error: RET / RETAA / RETAB cannot appear together in the same range.\n");
			_exit(EXIT_FAILURE);
		}
		v_ret_addr.push_back(i);
	}
	return v_ret_addr;
}