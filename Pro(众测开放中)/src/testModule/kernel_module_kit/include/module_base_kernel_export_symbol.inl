#pragma once
#include <atomic>
#include "kernel_module_kit_umbrella.h"
#include "module_math.h"
#include "aarch64_kernel_sym_call_helper.h"
#include <sys/system_properties.h>

/***************************************************************************
 * 这是 module_base_kernel_export_symbol.h 的实现部分
 ***************************************************************************/
namespace kernel_module {
KModErr hardware_virt_to_phys(uint64_t virt_kaddr, uint64_t & result);
KModErr __get_PAGE_OFFSET(uint64_t & result);
KModErr calibrate_vmemmap_dynamic(uint64_t & out_vmemmap, uint64_t & out_struct_page_size);
namespace export_symbol {
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;
using CallHelper = Aarch64KernelSymCallHelper;
using NeedReturnX0 = CallHelper::NeedReturnX0;

inline std::string get_system_property_7c20a6bec2a3baad94a2b20f71ea9844(const char* key) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(key, value);
    if (len <= 0) return {};
    return std::string(value, static_cast<size_t>(len));
}

inline bool is_huawei_b9277bc3a432f95fbc688de2bcd203d1() {
	std::string manufacturer = get_system_property_7c20a6bec2a3baad94a2b20f71ea9844("ro.product.manufacturer");
	std::string brand = get_system_property_7c20a6bec2a3baad94a2b20f71ea9844("ro.product.brand");
	std::transform(manufacturer.begin(), manufacturer.end(), manufacturer.begin(), [](unsigned char c){ return std::tolower(c); });
	std::transform(brand.begin(), brand.end(), brand.begin(), [](unsigned char c){ return std::tolower(c); });
	if (manufacturer.find("huawei") != std::string::npos || 
        manufacturer.find("honor") != std::string::npos ||
        brand.find("huawei") != std::string::npos || 
        brand.find("honor") != std::string::npos) {
        return true;
    }
	return false;
}

inline void emit_huawei_kti_add_ce72c7e634f27712ee84f3dd5e8e0ec9(Assembler* a, GpX x) {
	if (!is_huawei_b9277bc3a432f95fbc688de2bcd203d1()) return;
	static bool kallsyms_lookup_huawei_failed = true;
	static bool inited = false;
	if(inited && kallsyms_lookup_huawei_failed) return;
	inited = true;
	SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 pg;
	uint64_t kti_randomize_init_kaddr = 0;
	uint64_t kti_offset_kaddr = 0;
    if(is_failed(kernel_module::kallsyms_lookup_name("kti_randomize_init", kti_randomize_init_kaddr))) return;
    if(is_failed(kernel_module::kallsyms_lookup_name("kti_offset", kti_offset_kaddr))) return;
	RegProtectGuard g1(a, x1);
	aarch64_asm_mov_x(a, x1, kti_offset_kaddr);
	a->ldr(x1, ptr(x1));
	a->add(x, x, x1);
	kallsyms_lookup_huawei_failed = false;
}

inline void get_current(Assembler* a, GpX out_regs) {
	constexpr uint64_t kThreadSize = 0x4000;
	struct thread_info {
		uint64_t flags;
		uint64_t addr_limit;
		uint64_t task;
	};
	Label label_error = a->newLabel();
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	if (kernel_module::is_CONFIG_THREAD_INFO_IN_TASK()) {
		a->mrs(out_regs, sp_el0_id);
		emit_huawei_kti_add_ce72c7e634f27712ee84f3dd5e8e0ec9(a, out_regs);
		return;
	}
	if (kernel_module::is_CURRENT_FROM_SP_EL0_THREAD_INFO()) {
		a->mrs(out_regs, sp_el0_id);
		emit_huawei_kti_add_ce72c7e634f27712ee84f3dd5e8e0ec9(a, out_regs);
		a->ldr(out_regs, ptr(out_regs, offsetof(thread_info, task)));
		return;
	}
	a->mov(out_regs, sp);
	a->and_(out_regs, out_regs, Imm((uint64_t)~(kThreadSize - 1)));
	a->ldr(out_regs, ptr(out_regs, offsetof(thread_info, task)));
}

inline void get_current_thread_info(Assembler* a, GpX out_regs) {
	constexpr uint64_t kThreadSize = 0x4000;
	Label label_error = a->newLabel();
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	if (kernel_module::is_CONFIG_THREAD_INFO_IN_TASK()) {
		a->mrs(out_regs, sp_el0_id);
		emit_huawei_kti_add_ce72c7e634f27712ee84f3dd5e8e0ec9(a, out_regs);
		return;
	}
	if (kernel_module::is_CURRENT_FROM_SP_EL0_THREAD_INFO()) {
		a->mrs(out_regs, sp_el0_id);
		emit_huawei_kti_add_ce72c7e634f27712ee84f3dd5e8e0ec9(a, out_regs);
		return;
	}
	a->mov(out_regs, sp);
	a->and_(out_regs, out_regs, Imm((uint64_t)~(kThreadSize - 1)));
}

static const std::vector<std::string> copy_from_user_symbol_names = {
	"__arch_copy_from_user",	// Android 10+ / Kernel 4.14+ (GKI)
	"__copy_from_user",			// Android 7-9 / Kernel 3.18-4.9
	"_copy_from_user",			// 老内核 fallback (通常无 LTO，可用)
	"arm64_copy_from_user",		// 极少数异类
	"copy_from_user",			// 最后倔强
};

static const std::vector<std::string> copy_to_user_symbol_names = {
	"__arch_copy_to_user",	// Android 10+ / Kernel 4.14+ (GKI)
	"__copy_to_user",		// Android 7-9 / Kernel 3.18-4.9
	"_copy_to_user",		// 老内核 fallback (通常无 LTO，可用)
	"arm64_copy_to_user",	// 极少数异类
	"copy_to_user",			// 最后倔强
};

inline void copy_from_user(Assembler* a, KModErr & out_err, GpX to, GpX __user_from, GpX n) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_from_user_symbol_names,
		NeedReturnX0::Yes,
		to, __user_from, n
	);
}

inline void copy_from_user(Assembler* a, KModErr & out_err, GpX to, GpX __user_from, uint64_t n) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_from_user_symbol_names,
		NeedReturnX0::Yes,
		to, __user_from, n
	);
}

inline void copy_to_user(Assembler* a, KModErr & out_err, GpX __user_to, GpX from, GpX n) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_to_user_symbol_names,
		NeedReturnX0::Yes,
        __user_to, from, n
    );
}

inline void copy_to_user(Assembler* a, KModErr & out_err, GpX __user_to, GpX from, uint64_t n) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_to_user_symbol_names,
		NeedReturnX0::Yes,
        __user_to, from, n
    );
}


static const std::vector<std::string> copy_from_kernel_nofault_symbol_names = {
	"copy_from_kernel_nofault",	// Linux 5.8.0
	"probe_kernel_read",
	"__probe_kernel_read",
};

inline void copy_from_kernel_nofault(Assembler* a, KModErr& out_err, GpX dst, GpX src, GpX size) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_from_kernel_nofault_symbol_names,
		NeedReturnX0::Yes,
		dst, src, size
	);
}

inline void copy_from_kernel_nofault(Assembler* a, KModErr& out_err, GpX dst, GpX src, uint64_t size) {
	CallHelper::callSymbolCandidates(a, out_err,
		copy_from_kernel_nofault_symbol_names,
		NeedReturnX0::Yes,
		dst, src, size
	);
}

inline void printk(Assembler* a, KModErr & out_err, const char* fmt, const Arm64Arg* regs, int regs_count) {
	std::vector<Arm64Arg> __regs_vec(regs, regs + regs_count);
	IdleRegPool pool = IdleRegPool::makeFromVec(__regs_vec);
	GpX xFmt = pool.acquireX();
	RegProtectGuard g1(a, xFmt);
	aarch64_asm_set_x_cstr_ptr(a, xFmt, fmt);
	std::vector<Arm64Arg> new_regs = __regs_vec;
	new_regs.insert(new_regs.begin(), to_arg(xFmt));
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{"_printk"/*Linux kernel 5.15.0*/ , "printk"}),
		NeedReturnX0::No,
        new_regs
    );
}

inline void kallsyms_lookup_name(Assembler* a, KModErr & out_err, GpX name) {
    out_err = CallHelper::callNameAuto(a, "kallsyms_lookup_name", NeedReturnX0::Yes, name);
}

inline void kallsyms_lookup_size_offset(Assembler* a, KModErr& out_err, GpX addr, GpX symbolsize, GpX offset) {
    out_err = CallHelper::callNameAuto(a, "kallsyms_lookup_size_offset", NeedReturnX0::Yes, addr, symbolsize, offset);
}

inline void kallsyms_lookup_size_offset(Assembler* a, KModErr& out_err, uint64_t addr, GpX symbolsize, GpX offset) {
	out_err = CallHelper::callNameAuto(a, "kallsyms_lookup_size_offset", NeedReturnX0::Yes, addr, symbolsize, offset);
}

inline void kallsyms_on_each_symbol(Assembler* a, KModErr & out_err, SymbolCb fn, GpX data) {
	out_err = KModErr::ERR_MODULE_ASM;
	std::vector<uint8_t> callback_code;
	{
		aarch64_asm_ctx asm_ctx = init_aarch64_asm();
		auto b = asm_ctx.assembler();
		aarch64_asm_bit_c(b);
		b->mov(x10, x0);
		b->mov(x11, x1);
		b->mov(x12, x2);
		b->mov(x13, x3);
		fn(b, x10, x11, x12, x13);
		b->ret(x30);
		callback_code = aarch64_asm_to_bytes(a);
		if (callback_code.size() == 0) {
			out_err = KModErr::ERR_MODULE_ASM;
			return;
		}
	}
	IdleRegPool pool = IdleRegPool::make(data);
	GpX xCallback = pool.acquireX();
	RegProtectGuard g1(a, excluding_x0(pool.getUsed()));
	aarch64_asm_set_x_data_ptr(a, xCallback, callback_code);
	std::vector<Arm64Arg> new_regs;
	new_regs.push_back(to_arg(xCallback));
	new_regs.push_back(to_arg(data));
	out_err = CallHelper::callNameAuto(a, "kallsyms_on_each_symbol", NeedReturnX0::Yes, new_regs);
}

inline void get_task_mm(Assembler* a, KModErr & out_err, GpX task) {
    out_err = CallHelper::callNameAuto(a, "get_task_mm", NeedReturnX0::Yes, task);
}

inline void mmput(Assembler* a, KModErr & out_err, GpX mm) {
    out_err = CallHelper::callNameAuto(a, "mmput", NeedReturnX0::No, mm);
}


inline void find_vma(Assembler* a, KModErr& out_err, GpX mm, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "find_vma", NeedReturnX0::Yes, mm, addr);
}

inline void find_vma(Assembler* a, KModErr& out_err, GpX mm, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "find_vma", NeedReturnX0::Yes, mm, addr);
}

inline void find_vma(Assembler* a, KModErr& out_err, uint64_t mm, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "find_vma", NeedReturnX0::Yes, mm, addr);
}

inline void find_vm_area(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "find_vm_area", NeedReturnX0::Yes, addr);
}

inline void find_vm_area(Assembler* a, KModErr& out_err, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "find_vm_area", NeedReturnX0::Yes, addr);
}

inline void set_memory_ro(Assembler* a, KModErr & out_err, GpX addr, GpW numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_ro", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_ro(Assembler* a, KModErr & out_err, uint64_t addr, uint32_t numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_ro", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_rw(Assembler* a, KModErr & out_err, GpX addr, GpW numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_rw", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_rw(Assembler* a, KModErr & out_err, uint64_t addr, uint32_t numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_rw", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_nx(Assembler* a, KModErr & out_err, GpX addr, GpW numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_nx", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_nx(Assembler* a, KModErr & out_err, uint64_t addr, uint32_t numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_nx", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_x(Assembler* a, KModErr & out_err, GpX addr, GpW numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_x", NeedReturnX0::Yes, addr, numpages);
}

inline void set_memory_x(Assembler* a, KModErr & out_err, uint64_t addr, uint32_t numpages) {
    out_err = CallHelper::callNameAuto(a, "set_memory_x", NeedReturnX0::Yes, addr, numpages);
}

inline void kmalloc(Assembler* a, KModErr & out_err, GpX size, GpW flags) {
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{ "__kmalloc", "__kmalloc_noprof"/*Linux kernel 6.10*/ }),
		NeedReturnX0::Yes,
        size, flags
    );

}

inline void kmalloc(Assembler* a, KModErr & out_err, GpX size, KmallocFlags flags) {
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{ "__kmalloc", "__kmalloc_noprof"/*Linux kernel 6.10*/ }),
		NeedReturnX0::Yes,
        size, (uint32_t)flags
    );
}

inline void kmalloc(Assembler* a, KModErr & out_err, uint64_t size, KmallocFlags flags) {
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{ "__kmalloc", "__kmalloc_noprof"/*Linux kernel 6.10*/ }),
		NeedReturnX0::Yes,
        size, (uint32_t)flags
    );
}

inline KModErr kmalloc(uint64_t size, KmallocFlags flags, uint64_t& out_objp) {
    out_objp = 0;
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x11, size);
    aarch64_asm_mov_w(a, w12, (uint32_t)flags);
	kmalloc(a, out_err, x11, w12);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, out_objp));
	return KModErr::OK;
}

inline void kfree(Assembler* a, KModErr & out_err, GpX objp) {
    out_err = CallHelper::callNameAuto(a, "kfree", NeedReturnX0::No, objp);
}

inline KModErr kfree(uint64_t objp) {
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x11, objp);
	kfree(a, out_err, x11);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t return_value = 0;
	return kernel_module::execute_kernel_asm_func(bytes, return_value);
}

namespace linux_above_6_12_0 {
inline void execmem_alloc(Assembler* a, KModErr& out_err, GpW type, GpX size) {
	if(kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "execmem_alloc", NeedReturnX0::Yes, type, size);
}

inline void execmem_alloc(Assembler* a, KModErr& out_err, ExecmemTypes type, uint64_t size) {
	if(kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "execmem_alloc", NeedReturnX0::Yes, (uint32_t)type, size);
}

inline KModErr execmem_alloc(ExecmemTypes type, uint64_t size, uint64_t& out_ptr) {
	out_ptr = 0;
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_w(a, w11, (uint32_t)type);
    aarch64_asm_mov_x(a, x12, size);
	execmem_alloc(a, out_err, w11, x12);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, out_ptr));
	return KModErr::OK;
}

inline void execmem_free(Assembler* a, KModErr& out_err, GpX ptr) {
	if(kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "execmem_free", NeedReturnX0::No, ptr);
}

inline KModErr execmem_free(uint64_t ptr) {
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x11, ptr);
	export_symbol::linux_older::module_memfree(a, out_err, x11);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t return_value = 0;
	return kernel_module::execute_kernel_asm_func(bytes, return_value);
}
}

namespace linux_older {
inline void module_alloc(Assembler* a, KModErr & out_err, GpX size) {
	if(!kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "module_alloc", NeedReturnX0::Yes, size);
}

inline void module_alloc(Assembler* a, KModErr & out_err, uint64_t size) {
	if(!kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "module_alloc", NeedReturnX0::Yes, size);
}

inline KModErr module_alloc(uint64_t size, uint64_t& out_module_region) {
    out_module_region = 0;
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x11, size);
	module_alloc(a, out_err, x11);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, out_module_region));
	return KModErr::OK;
}

inline void module_memfree(Assembler* a, KModErr & out_err, GpX module_region) {
	if(!kernel_module::is_kernel_version_less("6.12.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
    out_err = CallHelper::callNameAuto(a, "module_memfree", NeedReturnX0::No, module_region);
}

inline KModErr module_memfree(uint64_t module_region) {
	KModErr out_err = KModErr::OK;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_cycle = a->newLabel();
	arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(a, x11, module_region);
	module_memfree(a, out_err, x11);
	RETURN_IF_ERROR(out_err);
	arm64_module_asm_func_end(a);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    uint64_t return_value = 0;
	return kernel_module::execute_kernel_asm_func(bytes, return_value);
}
}

namespace linux_above_4_9_0 {
inline void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, GpW len, GpW gup_flags) {
	if (is_kernel_version_less("4.9.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "access_process_vm", NeedReturnX0::Yes, tsk, addr, buf, len, gup_flags);
}
inline void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, uint32_t len, GpW gup_flags) {
	if (is_kernel_version_less("4.9.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "access_process_vm", NeedReturnX0::Yes, tsk, addr, buf, len, gup_flags);
}
}

namespace linux_older {
inline void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, GpW len, GpW write) {
	if (!is_kernel_version_less("4.9.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "access_process_vm", NeedReturnX0::Yes, tsk, addr, buf, len, write);
}
inline void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, uint32_t len, GpW write) {
	if (!is_kernel_version_less("4.9.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "access_process_vm", NeedReturnX0::Yes, tsk, addr, buf, len, write);
}
}

inline void seq_printf(Assembler* a, KModErr & out_err, GpX m, GpX f, const Arm64Arg* regs, int regs_count) {
	std::vector<Arm64Arg> __regs_vec(regs, regs + regs_count);
	__regs_vec.insert(__regs_vec.begin(), to_arg(f));
	__regs_vec.insert(__regs_vec.begin(), to_arg(m));
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{"seq_printf"}),
		NeedReturnX0::No,
        __regs_vec
    );
}

inline void seq_printf(Assembler* a, KModErr & out_err, GpX m, const char *f, const Arm64Arg* regs, int regs_count) {
	std::vector<Arm64Arg> __regs_vec(regs, regs + regs_count);
	IdleRegPool pool = IdleRegPool::makeFromVec(__regs_vec);
	GpX xM = pool.acquireX();
	GpX xF = pool.acquireX();
	RegProtectGuard g1(a, xM, xF);
	a->mov(xM, m);
	aarch64_asm_set_x_cstr_ptr(a, xF, f);
	std::vector<Arm64Arg> new_regs = __regs_vec;
	new_regs.insert(new_regs.begin(), to_arg(xF));
	new_regs.insert(new_regs.begin(), to_arg(xM));
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{"seq_printf"}),
		NeedReturnX0::No,
        new_regs
    );
}

namespace linux_above_5_6_0 {
inline void pin_user_pages_fast(Assembler* a, KModErr& out_err, GpX start, GpW nr_pages, GpW gup_flags, GpX pages) {
	if (is_kernel_version_less("5.6.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "pin_user_pages_fast", NeedReturnX0::Yes, start, nr_pages, gup_flags, pages);
}
}

namespace linux_above_5_2_0 {
inline void get_user_pages_fast(Assembler* a, KModErr& out_err, GpX start, GpW nr_pages, GpW gup_flags, GpX pages) {
	if (is_kernel_version_less("5.2.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "get_user_pages_fast", NeedReturnX0::Yes, start, nr_pages, gup_flags, pages);
}
}
namespace linux_older {
inline void get_user_pages_fast(Assembler* a, KModErr& out_err, GpX start, GpW nr_pages, GpW write, GpX pages) {
	if (!is_kernel_version_less("5.2.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "get_user_pages_fast", NeedReturnX0::Yes, start, nr_pages, write, pages);
}
}

inline void aarch64_insn_write(Assembler* a, KModErr & out_err, GpX addr, GpW insn) {
    out_err = CallHelper::callNameAuto(a, "aarch64_insn_write", NeedReturnX0::Yes, addr, insn);
}

inline void aarch64_insn_patch_text(Assembler* a, KModErr & out_err, GpX addrs, GpX insns, GpW cnt) {
    out_err = CallHelper::callNameAuto(a, "aarch64_insn_patch_text", NeedReturnX0::Yes, addrs, insns, cnt);
}

inline void kern_path(Assembler* a, KModErr & out_err, GpX name, GpW flags, GpX path) {
    out_err = CallHelper::callNameAuto(a, "kern_path", NeedReturnX0::Yes, name, flags, path);
}

inline void kern_path(Assembler* a, KModErr & out_err, GpX name, LookupFlags flags, GpX path) {
	out_err = CallHelper::callNameAuto(a, "kern_path", NeedReturnX0::Yes, name, (uint32_t)flags, path);
}

inline void kern_path(Assembler* a, KModErr & out_err, GpX name, LookupFlags flags, uint64_t path_buf_addr) {
	out_err = CallHelper::callNameAuto(a, "kern_path", NeedReturnX0::Yes, name, (uint32_t)flags, path_buf_addr);
}

inline void path_put(Assembler* a, KModErr& out_err, GpX ptr_path) {
	out_err = CallHelper::callNameAuto(a, "path_put", NeedReturnX0::No, ptr_path);
}

inline void path_put(Assembler* a, KModErr& out_err, uint64_t ptr_path) {
	out_err = CallHelper::callNameAuto(a, "path_put", NeedReturnX0::No, ptr_path);
}

inline void d_path(Assembler* a, KModErr & out_err, GpX path, GpX buf, GpW buflen) {
    out_err = CallHelper::callNameAuto(a, "d_path", NeedReturnX0::Yes, path, buf, buflen);
}

inline void d_path(Assembler* a, KModErr & out_err, GpX path, GpX buf, uint32_t buflen) {
	out_err = CallHelper::callNameAuto(a, "d_path", NeedReturnX0::Yes, path, buf, buflen);
}

inline void find_get_pid(Assembler* a, KModErr & out_err, GpW nr) {
    out_err = CallHelper::callNameAuto(a, "find_get_pid", NeedReturnX0::Yes, nr);
}

inline void put_pid(Assembler* a, KModErr & out_err, GpX pid) {
    out_err = CallHelper::callNameAuto(a, "put_pid", NeedReturnX0::No, pid);
}

inline void find_vpid(Assembler* a, KModErr& out_err, GpW nr) {
	out_err = CallHelper::callNameAuto(a, "find_vpid", NeedReturnX0::Yes, nr);
}

inline void pid_vnr(Assembler* a, KModErr& out_err, GpX pid) {
	out_err = CallHelper::callNameAuto(a, "pid_vnr", NeedReturnX0::Yes, pid);
}

namespace linux_above_4_19_0 {
inline void pid_task(Assembler* a, KModErr& out_err, GpX pid, GpW type) {
	if (is_kernel_version_less("4.19.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "pid_task", NeedReturnX0::Yes, pid, type);
}
inline void pid_task(Assembler* a, KModErr& out_err, GpX pid, PidType type) {
	if (is_kernel_version_less("4.19.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "pid_task", NeedReturnX0::Yes, pid, (uint32_t)type);
}
}

namespace linux_older {
inline void pid_task(Assembler* a, KModErr& out_err, GpX pid, GpW type) {
	if (!is_kernel_version_less("4.19.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "pid_task", NeedReturnX0::Yes, pid, type);
}
inline void pid_task(Assembler* a, KModErr& out_err, GpX pid, PidType type) {
	if (!is_kernel_version_less("4.19.0")) {
		out_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
		return;
	}
	out_err = CallHelper::callNameAuto(a, "pid_task", NeedReturnX0::Yes, pid, (uint32_t)type);
}
}

inline void proc_mkdir(Assembler* a, KModErr& out_err, GpX name, GpX parent) {
	out_err = CallHelper::callNameAuto(a, "proc_mkdir", NeedReturnX0::Yes, name, parent);
}

namespace linux_above_5_6_0 {
inline void proc_create(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_fops) {
	out_err = CallHelper::callNameAuto(a, "proc_create", NeedReturnX0::Yes, name, mode, parent, proc_fops);
}
inline void proc_create_data(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_ops, GpX data) {
	out_err = CallHelper::callNameAuto(a, "proc_create_data", NeedReturnX0::Yes, name, mode, parent, proc_ops, data);
}
}

namespace linux_older {
inline void proc_create(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_fops) {
	out_err = CallHelper::callNameAuto(a, "proc_create", NeedReturnX0::Yes, name, mode, parent, proc_fops);
}
inline void proc_create_data(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_ops, GpX data) {
	out_err = CallHelper::callNameAuto(a, "proc_create_data", NeedReturnX0::Yes, name, mode, parent, proc_ops, data);
}
}

inline void proc_remove(Assembler* a, KModErr& out_err, GpX de) {
	out_err = CallHelper::callNameAuto(a, "proc_remove", NeedReturnX0::No, de);
}

#define STATX_BASIC_STATS	0x000007ffU	/* The stuff in the normal stat struct */
inline void vfs_fstat(Assembler* a, KModErr& out_err, GpW fd, GpX stat) {
	if(kernel_module::is_kernel_version_less("4.11.0")) {
		out_err = CallHelper::callNameAuto(a, "vfs_fstat", NeedReturnX0::Yes, fd, stat);
		return;
	} else if(kernel_module::is_kernel_version_less("5.10.0")) {
		out_err = CallHelper::callNameAuto(a, "vfs_statx_fd", NeedReturnX0::Yes, fd, stat, (uint32_t)STATX_BASIC_STATS, (uint32_t)0);
		return;
	} else {
		out_err = CallHelper::callNameAuto(a, "vfs_fstat", NeedReturnX0::Yes, fd, stat);
		return;
	}
}

inline void misc_register(Assembler* a, KModErr& out_err, GpX misc) {
	out_err = CallHelper::callNameAuto(a, "misc_register", NeedReturnX0::Yes, misc);
}

inline void misc_deregister(Assembler* a, KModErr& out_err, GpX misc) {
	out_err = CallHelper::callNameAuto(a, "misc_deregister", NeedReturnX0::No, misc);
}

inline void down_write(Assembler* a, KModErr& out_err, GpX sem) {
	out_err = CallHelper::callNameAuto(a, "down_write", NeedReturnX0::No, sem);
}

inline void up_read(Assembler* a, KModErr& out_err, GpX sem) {
	out_err = CallHelper::callNameAuto(a, "up_read", NeedReturnX0::No, sem);
}

inline void mutex_lock(Assembler* a, KModErr& out_err, GpX lock) {
	out_err = CallHelper::callNameAuto(a, "mutex_lock", NeedReturnX0::No, lock);
}

inline void mutex_unlock(Assembler* a, KModErr& out_err, GpX lock) {
	out_err = CallHelper::callNameAuto(a, "mutex_unlock", NeedReturnX0::No, lock);
}

inline void ihold(Assembler* a, KModErr& out_err, GpX inode) {
	out_err = CallHelper::callNameAuto(a, "ihold", NeedReturnX0::No, inode);
}

inline void igrab(Assembler* a, KModErr& out_err, GpX inode) {
	out_err = CallHelper::callNameAuto(a, "igrab", NeedReturnX0::Yes, inode);
}

inline void iput(Assembler* a, KModErr& out_err, GpX inode) {
	out_err = CallHelper::callNameAuto(a, "iput", NeedReturnX0::No, inode);
}


inline void local_irq_save(Assembler* a, GpX out_store_flags_reg) {
	aarch64_asm_mrs_daif(a, out_store_flags_reg);
	aarch64_asm_msr_daifset(a, 2); // Disable IRQ
}

inline void local_irq_restore(Assembler* a, GpX flags) {
	aarch64_asm_msr_daif(a, flags);
}

inline void invalidate_inode_pages2(Assembler* a, KModErr& out_err, GpX mapping) {
	out_err = CallHelper::callNameAuto(a, "invalidate_inode_pages2", NeedReturnX0::Yes, mapping);
}

inline void get_kprobe(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "get_kprobe", NeedReturnX0::Yes, addr);
}

inline void apply_to_page_range(Assembler* a, KModErr& out_err, GpX mm, GpX addr, GpX size, GpX fn, GpX data) {
	out_err = CallHelper::callNameAuto(a, "apply_to_page_range", NeedReturnX0::Yes, mm, addr, size, fn, data);
}

inline void apply_to_existing_page_range(Assembler* a, KModErr& out_err, GpX mm, GpX addr, GpX size, GpX fn, GpX data) {
	out_err = CallHelper::callNameAuto(a, "apply_to_existing_page_range", NeedReturnX0::Yes, mm, addr, size, fn, data);
}

inline KModErr get_PHYS_OFFSET(uint64_t & result) {
	uint64_t kaddr;
	RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("memstart_addr", kaddr));
	return kernel_module::read_kernel_mem(kaddr, &result, sizeof(result));
}

inline KModErr get_PAGE_OFFSET(uint64_t& result) {
    static std::atomic<uint64_t> last_result{0};
    uint64_t cached = last_result.load(std::memory_order_acquire);
    if (cached == 0) {
        uint64_t r = 0;
        RETURN_IF_ERROR(::kernel_module::__get_PAGE_OFFSET(r));
        last_result.store(r, std::memory_order_release);
        cached = r;
    }
    result = cached;
    return KModErr::OK;
}

inline KModErr virt_to_phys(uint64_t virt_kaddr, uint64_t & result) {
	// 生成纯净的 Page Mask，并将 va 对齐到“页头”
    // 例如 4K 页 (4096)，减 1 是 0xFFF，取反就是 ~0xFFF (0xFFFFFFFFFFFFF000)
    // 这样既能抹平低位，又能完美保留高位的 0xFFFF...
    uint64_t page_mask = ~((uint64_t)kernel_module::get_page_size() - 1); 
    uint64_t va_aligned = virt_kaddr & page_mask;
    uint64_t va_page_off = virt_kaddr - va_aligned;
    // 将对齐后的页头虚拟地址，传入硬件翻译
    uint64_t pa = 0;
    RETURN_IF_ERROR(kernel_module::hardware_virt_to_phys(va_aligned, pa));
    if (!pa) return KModErr::ERR_MODULE_NOT_KADDR;
	result = pa + va_page_off;
	return KModErr::OK;
}

inline KModErr phys_to_virt(uint64_t phys_addr, uint64_t & result) {
	SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 s;
    uint64_t physvirt_offset = 0;
    if(is_ok(kernel_module::kallsyms_lookup_name("physvirt_offset", physvirt_offset)) && physvirt_offset) {
		uint64_t physvirt_offset_val = 0;
		RETURN_IF_ERROR(kernel_module::read_kernel_mem(physvirt_offset, &physvirt_offset_val, sizeof(physvirt_offset_val)));
		result = phys_addr - physvirt_offset_val;
		return KModErr::OK;
	}
    uint64_t PHYS_OFFSET = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::get_PHYS_OFFSET(PHYS_OFFSET));
    uint64_t PAGE_OFFSET = 0;
    RETURN_IF_ERROR(kernel_module::export_symbol::get_PAGE_OFFSET(PAGE_OFFSET));
    if(kernel_module::is_kernel_version_less("4.6.0")) {
        result = phys_addr - PHYS_OFFSET + PAGE_OFFSET;
    } else {
        result = (phys_addr - PHYS_OFFSET) | PAGE_OFFSET;
    }
	return KModErr::OK;
}

inline KModErr get_vmemmap(uint64_t & result) {
	uint64_t s;
	return ::kernel_module::calibrate_vmemmap_dynamic(result, s);
}

inline KModErr android_arm64_page_to_pfn(uint64_t page, uint64_t & result) {
	uint64_t vmemmap = 0;
	RETURN_IF_ERROR(get_vmemmap(vmemmap));
	uint32_t struct_page_size = 0;
	RETURN_IF_ERROR(kernel_module::get_struct_page_size(struct_page_size));
	uint64_t byte_offset = page - vmemmap;
	result = byte_offset / struct_page_size;
	return KModErr::OK;
}

inline KModErr pfn_to_phys(uint64_t pfn, uint64_t & result) {
	result = pfn << PAGE_SHIFT;
	return KModErr::OK;
}

inline void vmalloc(Assembler* a, KModErr& out_err, GpX size) {
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{ "vmalloc", "vmalloc_noprof"/*Linux kernel 6.10*/}),
		NeedReturnX0::Yes,
        size
    );

}

inline void vmalloc(Assembler* a, KModErr& out_err, uint64_t size) {
	CallHelper::callSymbolCandidates(a, out_err,
        (std::vector<std::string>{ "vmalloc", "vmalloc_noprof"/*Linux kernel 6.10*/}),
		NeedReturnX0::Yes,
        size
    );

}

inline void vfree(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "vfree", NeedReturnX0::Yes, addr);
}

inline void vfree(Assembler* a, KModErr& out_err, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "vfree", NeedReturnX0::Yes, addr);
}

inline void vmalloc_to_page(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "vmalloc_to_page", NeedReturnX0::Yes, addr);
}

inline void vmalloc_to_page(Assembler* a, KModErr& out_err, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "vmalloc_to_page", NeedReturnX0::Yes, addr);
}

inline void vmalloc_to_pfn(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "vmalloc_to_pfn", NeedReturnX0::Yes, addr);
}

inline void vmalloc_to_pfn(Assembler* a, KModErr& out_err, uint64_t addr) {
	out_err = CallHelper::callNameAuto(a, "vmalloc_to_pfn", NeedReturnX0::Yes, addr);
}

inline void pfn_pte(Assembler* a, GpX pfn, GpX prot) {
	IdleRegPool pool = IdleRegPool::make(x0, pfn, prot);
	GpX xTempPfn = pool.acquireX();
	GpX xTempProt = pool.acquireX();
	RegProtectGuard g1(a, excluding_x0(pool.getUsed()));
	a->mov(xTempPfn, pfn);
	a->mov(xTempProt, prot);
	a->lsl(x0, xTempPfn, PAGE_SHIFT);
	a->orr(x0, x0, xTempProt);
}

inline void pfn_pte(Assembler* a, GpX pfn, uint64_t prot_val) {
	IdleRegPool pool = IdleRegPool::make(pfn);
	GpX xProt = pool.acquireX();
	aarch64_asm_mov_x(a, xProt, prot_val);
	pfn_pte(a, pfn, xProt);
}

inline void I_BDEV(Assembler* a, KModErr& out_err, GpX inode) {
	out_err = CallHelper::callNameAuto(a, "I_BDEV", NeedReturnX0::Yes, inode);
}

inline void I_BDEV(Assembler* a, KModErr& out_err, uint64_t inode_kaddr) {
	out_err = CallHelper::callNameAuto(a, "I_BDEV", NeedReturnX0::Yes, inode_kaddr);
}


namespace linux_above_4_17_0 {
inline void selinux_kernel_status_page(Assembler* a, KModErr& out_err, GpX state) {
	out_err = CallHelper::callNameAuto(a, "selinux_kernel_status_page", NeedReturnX0::Yes, state);
}
}
namespace linux_older {
inline void selinux_kernel_status_page(Assembler* a, KModErr& out_err) {
	out_err = CallHelper::callNameAuto(a, "selinux_kernel_status_page", NeedReturnX0::Yes);
}
}

inline void vmap(Assembler* a, KModErr& out_err, GpX pages, GpW count, GpX flags, GpX prot) {
	out_err = CallHelper::callNameAuto(a, "vmap", NeedReturnX0::Yes, pages, count, flags, prot);
}

inline void vunmap(Assembler* a, KModErr& out_err, GpX addr) {
	out_err = CallHelper::callNameAuto(a, "vunmap", NeedReturnX0::No, addr);
}

inline void dump_stack(Assembler* a, KModErr& out_err) {
	out_err = CallHelper::callNameAuto(a, "dump_stack", NeedReturnX0::No);
}

} // namespace export_symbol
} // namespace kernel_module
