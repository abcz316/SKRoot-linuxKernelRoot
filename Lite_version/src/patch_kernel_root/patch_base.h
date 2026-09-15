#pragma once
#include <iostream>
#include <vector>
#include <functional>
#include "patch_kernel_root.h"
#include "3rdparty/aarch64_asm_helper.h"
#include "3rdparty/aarch64_asm_reg_protect_guard.h"
#include "analyze/symbol_analyze.h"
#include "analyze/init_cred_searcher.h"

#define THREAD_SIZE 0x4000

struct huawei_extra {
	uint64_t kti_addr = 0;
};

struct thread_info {
	uint64_t flags;
	uint64_t addr_limit;
	uint64_t task;
};

class PatchBase {
public:
	PatchBase(const std::vector<char>& file_buf, size_t cred_uid_offset, const huawei_extra& huawei);
	PatchBase(const PatchBase& other);
	~PatchBase();
	uint32_t skip_pac_bti_at_func_start(uint32_t addr);
	SymbolRegion skip_pac_bti_at_func_start(const SymbolRegion& sym);
	size_t patch_jump(size_t patch_addr, size_t jump_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

	std::vector<size_t> find_all_aarch64_ret_offsets(size_t offset, size_t size);
	uint32_t find_func_epilogue_offset(uint32_t func_start_off, uint32_t func_size);

protected:
	bool is_CONFIG_THREAD_INFO_IN_TASK();
	bool is_CURRENT_FROM_SP_EL0_THREAD_INFO();
	void emit_get_current(asmjit::a64::Assembler* a, asmjit::a64::GpX x);
	void emit_safe_bl(asmjit::a64::Assembler* a, size_t func_base_addr, size_t target);
	std::vector<uint8_t> assemble_aarch64(std::function<void(asmjit::a64::Assembler* a)> fn);

	int count_mrs_sp_el0();

	bool is_huawei();
	void update_huawei_kti_calc_base(size_t base);
	void emit_huawei_kti_add(asmjit::a64::Assembler* a, asmjit::a64::GpX x);

	const std::vector<char>& m_file_buf;
	KernelVersionParser m_kernel_ver_parser;
	InitCredSearcher m_init_cred_searcher;
	huawei_extra m_huawei_extra;
	size_t m_huawei_kti_calc_base = 0;
};