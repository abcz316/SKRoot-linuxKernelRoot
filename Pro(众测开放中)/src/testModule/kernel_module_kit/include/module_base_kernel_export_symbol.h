#pragma once
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <vector>
#include "kernel_module_kit_umbrella.h"
#include "aarch64_asm_arg.h"

/***************************************************************************
 * 内核导出符号（exported symbols）调用封装
 *
 * 功能：简化内核导出符号调用，统一入口。外部调用无需关心符号解析、寻址、传参序列等细节，让上层逻辑更专注于业务流程。
 *
 * 实现：细节位于 module_base_kernel_export_symbol.inl（可按需扩展更多符号封装）。
 *
 * 寄存器说明：
 *    X0 可作为入参寄存器使用；调用结束后 X0 存放返回值（因此会被改写/覆盖）；
 *    X1～X17、X29、X30 调用前后值保持不变（外部无需保护）；
 *    X18～X28 可能被内部用作临时寄存器并被改写；如需保持请由调用方自行保护。
 *
 * 错误处理：out_err 用于回传错误码（成功为 OK），接收寻址失败等错误信息；调用方可据此决定是否继续生成后续指令。
 * 
 * 用法示例：
 * {
 *   RegProtectGuard g1(a, x0);  // 保存 X0 原值，作用域结束恢复；避免被下方返回值覆盖
 *   aarch64_asm_mov_x(a, x1, 128);
 *   export_symbol::kmalloc(a, err, x1, KmallocFlags::GFP_KERNEL);
 *   RETURN_IF_ERROR(err);       // 若符号寻址/调用失败则中止生成
 *   a->mov(x10, x0);            // 将返回值转存到 X10，供作用域外使用
 * }
 * a->cbz(x10, L_equal);        // 通过 X10 判断返回值
 ***************************************************************************/
namespace kernel_module {
namespace export_symbol {
using namespace asmjit::a64;
// 原型：struct task_struct *get_current(void);，获取current指针并赋值到寄存器x，需判空，因为kthread无法获取。无返回值。
void get_current(Assembler* a, GpX x);

// 原型：unsigned long copy_from_user(void *to, const void __user *from, unsigned long n); 返回值为 X0 寄存器
void copy_from_user(Assembler* a, KModErr& out_err, GpX to, GpX __user_from, GpX n);
void copy_from_user(Assembler* a, KModErr& out_err, GpX to, GpX __user_from, uint64_t n);

// 原型：unsigned long copy_to_user(void __user *to, const void *from, unsigned long n); 返回值为 X0 寄存器
void copy_to_user(Assembler* a, KModErr& out_err, GpX __user_to, GpX from, GpX n);
void copy_to_user(Assembler* a, KModErr& out_err, GpX __user_to, GpX from, uint64_t n);

// 原型：void printk(const char *fmt, ...); 无返回值
template <typename... Regs>
void printk(Assembler* a, KModErr& out_err, const char *fmt, Regs... regs) {
    auto orig = mk_args(std::forward<Regs>(regs)...);
    void printk(Assembler* a, KModErr& out_err, const char *fmt, const Arm64Arg* regs, int regs_count);
    printk(a, out_err, fmt, orig.data(), static_cast<int>(orig.size()));
}

// 原型：int fn(void *data, const char *name, struct module *mod, unsigned long addr)，设置末尾 X0 返回值非0代表终止遍历。
typedef void (*SymbolCb)(
    Assembler* a, // Assembler 对象，用于生成 ARM64 指令
    GpX data,     // 用户数据寄存器，对应 void* data
    GpX name_ptr, // 符号名指针寄存器，指向内核符号字符串
    GpX mod,      // 符号所属模块(struct module*)寄存器，可能为 NULL
    GpX addr      // 符号地址寄存器
);
// 原型: int kallsyms_on_each_symbol(int (*fn)(void * data, const char * name, struct module *mod, unsigned long addr), void *data); 返回值为 X0 寄存器
void kallsyms_on_each_symbol(Assembler* a, KModErr& out_err, SymbolCb fn, GpX data);

// 原型: struct mm_struct *get_task_mm(struct task_struct *task); 返回值为 X0 寄存器
void get_task_mm(Assembler* a, KModErr& out_err, GpX task);

// 原型: void mmput(struct mm_struct *mm) 无返回值
void mmput(Assembler* a, KModErr& out_err, GpX mm);

// 原型：struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr); 返回值为 X0 寄存器
void find_vma(Assembler* a, KModErr& out_err, GpX mm, GpX addr);
void find_vma(Assembler* a, KModErr& out_err, GpX mm, uint64_t addr);
void find_vma(Assembler* a, KModErr& out_err, uint64_t mm, uint64_t addr);

// 原型: int set_memory_ro(unsigned long addr, int numpages); 返回值为 W0 寄存器
void set_memory_ro(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);
void set_memory_ro(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);

// 原型: int set_memory_rw(unsigned long addr, int numpages); 返回值为 W0 寄存器
void set_memory_rw(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);
void set_memory_rw(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);

// 原型: int set_memory_nx(unsigned long addr, int numpages); 返回值为 W0 寄存器
void set_memory_nx(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);
void set_memory_nx(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);

// 原型: int set_memory_x(unsigned long addr, int numpages); 返回值为 W0 寄存器
void set_memory_x(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);
void set_memory_x(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);

enum class KmallocFlags : uint32_t {
    GFP_KERNEL = 0,        // 默认的内存分配标志
    GFP_ATOMIC = 1,        // 不允许阻塞的内存分配
    GFP_HIGHUSER = 2,      // 高端用户内存
    GFP_DMA = 4,           // 支持 DMA 的内存
    GFP_USER = 8,          // 用户空间内存
    GFP_RECLAIMABLE = 16,  // 可回收的内存
    GFP_ZERO = 32          // 分配内存并清零
};
// 原型：void * kmalloc(size_t size, gfp_t flags); 返回值为 X0 寄存器
void kmalloc(Assembler* a, KModErr& out_err, GpX size, GpW flags);
void kmalloc(Assembler* a, KModErr& out_err, GpX size, KmallocFlags flags);
void kmalloc(Assembler* a, KModErr& out_err, uint64_t size, KmallocFlags flags);
// kmalloc (外部封装版本)：申请内核内存，结果写入 out_objp，返回值为 OK 代表执行成功
KModErr kmalloc(uint64_t size, KmallocFlags flags, uint64_t& out_objp);

// 原型：void kfree(const void *objp) 无返回值
void kfree(Assembler* a, KModErr& out_err, GpX objp);
// kfree (外部封装版本)：释放内核内存，返回值为 OK 代表执行成功
KModErr kfree(uint64_t objp);

namespace linux_above_6_12_0 {
enum class ExecmemTypes : uint32_t {
    EXECMEM_DEFAULT = 0,
	EXECMEM_MODULE_TEXT = EXECMEM_DEFAULT,
	EXECMEM_KPROBES,
	EXECMEM_FTRACE,
	EXECMEM_BPF,
	EXECMEM_MODULE_DATA,
	EXECMEM_TYPE_MAX,
};
// 原型：void *execmem_alloc(enum execmem_type type, size_t size); 返回值为 X0 寄存器
void execmem_alloc(Assembler* a, KModErr& out_err, GpW type, GpX size);
void execmem_alloc(Assembler* a, KModErr& out_err, ExecmemTypes type, uint64_t size);
// execmem_alloc (外部封装版本)：申请内核内存，结果写入 out_ptr，返回值为 OK 代表执行成功
KModErr execmem_alloc(ExecmemTypes type, uint64_t size, uint64_t& out_ptr);

// 原型：void execmem_free(void *ptr); 无返回值
void execmem_free(Assembler* a, KModErr& out_err, GpX ptr);
// execmem_free (外部封装版本)：释放内核内存，返回值为 OK 代表执行成功
KModErr execmem_free(uint64_t ptr);
}

namespace linux_older {
// 原型：void *module_alloc(unsigned long size); 返回值为 X0 寄存器
void module_alloc(Assembler* a, KModErr& out_err, GpX size);
void module_alloc(Assembler* a, KModErr& out_err, uint64_t size);
// module_alloc (外部封装版本)：申请内核内存，结果写入 out_module_region，返回值为 OK 代表执行成功
KModErr module_alloc(uint64_t size, uint64_t& out_module_region);

// 原型：void module_memfree(void *module_region); 无返回值
void module_memfree(Assembler* a, KModErr& out_err, GpX module_region);
// module_memfree (外部封装版本)：释放内核内存，返回值为 OK g'd
KModErr module_memfree(uint64_t module_region);
}


namespace linux_above_4_9_0 {
// 原型: int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags); 返回值为 W0 寄存器
void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, GpW len, GpW gup_flags);
void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, uint32_t len, GpW gup_flags);
}
namespace linux_older {
// 原型: int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write); 返回值为 W0 寄存器
void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, GpW len, GpW write);
void access_process_vm(Assembler* a, KModErr& out_err, GpX tsk, GpX addr, GpX buf, uint32_t len, GpW write);
}

void access_process_vm(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t insn);

// 原型: int __kprobes aarch64_insn_write(void *addr, u32 insn); 返回值为 W0 寄存器
void aarch64_insn_write(Assembler* a, KModErr& out_err, GpX addr, GpW insn);

// 原型: int __kprobes aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt); 返回值为 W0 寄存器
void aarch64_insn_patch_text(Assembler* a, KModErr & out_err, GpX addrs, GpX insns, GpW cnt);

enum class LookupFlags : uint32_t {
    LOOKUP_FOLLOW = 0x0001,	/* follow links at the end */
    LOOKUP_DIRECTORY = 0x0002,	/* require a directory */
    LOOKUP_AUTOMOUNT = 0x0004,  /* force terminal automount */
};
// 原型：int kern_path(const char *name, unsigned int flags, struct path *path); 返回值为 W0 寄存器
void kern_path(Assembler* a, KModErr& out_err, GpX name, GpW flags, GpX path);
void kern_path(Assembler* a, KModErr& out_err, GpX name, LookupFlags flags, GpX path);
void kern_path(Assembler* a, KModErr& out_err, GpX name, LookupFlags flags, uint64_t path_buf_addr);

// 原型：void path_put(const struct path *path); 无返回值
void path_put(Assembler* a, KModErr& out_err, GpX ptr_path);
void path_put(Assembler* a, KModErr& out_err, uint64_t ptr_path);

// 原型：char *d_path(const struct path *path, char *buf, int buflen); 返回值为 X0 寄存器
void d_path(Assembler* a, KModErr & out_err, GpX path, GpX buf, GpW buflen);
void d_path(Assembler* a, KModErr & out_err, GpX path, GpX buf, uint32_t buflen);

// 原型: struct pid *find_get_pid(pid_t nr); 返回值为 X0 寄存器
void find_get_pid(Assembler* a, KModErr & out_err, GpW nr);

// 原型: void put_pid(struct pid *pid)，无返回值
void put_pid(Assembler* a, KModErr & out_err, GpX pid);

// 原型：struct pid *find_vpid(int nr); 返回值为 X0 寄存器
void find_vpid(Assembler* a, KModErr& out_err, GpW nr);

// 原型：pid_t pid_vnr(struct pid *pid); 返回值为 X0 寄存器
void pid_vnr(Assembler* a, KModErr& out_err, GpX pid);

namespace linux_above_4_19_0 {
enum class PidType : uint32_t {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX,
};
// 原型: struct task_struct *pid_task(struct pid *pid, enum pid_type type); 返回值为 X0 寄存器
void pid_task(Assembler* a, KModErr& out_err, GpX pid, GpW type);
void pid_task(Assembler* a, KModErr& out_err, GpX pid, PidType type);
}
namespace linux_older {
enum class PidType : uint32_t {
	PIDTYPE_PID = 0,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};
// 原型: struct task_struct *pid_task(struct pid *pid, enum pid_type type); 返回值为 X0 寄存器
void pid_task(Assembler* a, KModErr& out_err, GpX pid, GpW type);
void pid_task(Assembler* a, KModErr& out_err, GpX pid, PidType type);
}

// 原型：struct proc_dir_entry *proc_mkdir(const char *name, struct proc_dir_entry *parent); 返回值为 X0 寄存器
void proc_mkdir(Assembler* a, KModErr& out_err, GpX name, GpX parent);


namespace linux_above_5_6_0 {
// 原型：struct proc_dir_entry *proc_create(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops); 返回值为 X0 寄存器
void proc_create(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_fops);

// 原型：struct proc_dir_entry *proc_create_data(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops, void *data); 返回值为 X0 寄存器
void proc_create_data(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_ops, GpX data);
}

namespace linux_older {
// 原型：struct proc_dir_entry *proc_create(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops); 返回值为 X0 寄存器
void proc_create(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_fops);

// 原型：struct proc_dir_entry *proc_create_data(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops, void *data); 返回值为 X0 寄存器
void proc_create_data(Assembler* a, KModErr& out_err, GpX name, GpW mode, GpX parent, GpX proc_ops, GpX data);
}

// 原型：void proc_remove(struct proc_dir_entry *de); 无返回值
void proc_remove(Assembler* a, KModErr& out_err, GpX de);

// 原型：int misc_register(struct miscdevice *misc); 返回值为 W0 寄存器
// 原型：void misc_deregister(struct miscdevice *misc); 无返回值
void misc_register(Assembler* a, KModErr& out_err, GpX misc);
void misc_deregister(Assembler* a, KModErr& out_err, GpX misc);

// 原型：void down_write(struct rw_semaphore *sem); 无返回值
// 原型：void up_read(struct rw_semaphore *sem); 无返回值
void down_write(Assembler* a, KModErr& out_err, GpX sem);
void up_read(Assembler* a, KModErr& out_err, GpX sem);

// 原型：void mutex_lock(struct mutex *lock); 无返回值
// 原型：void mutex_unlock(struct mutex *lock); 无返回值
void mutex_lock(Assembler* a, KModErr& out_err, GpX lock);
void mutex_unlock(Assembler* a, KModErr& out_err, GpX lock);

// 原型：void ihold(struct inode *inode); 无返回值
void ihold(Assembler* a, KModErr& out_err, GpX inode);

// 原型：struct inode *igrab(struct inode *inode); 返回值为 X0 寄存器
void igrab(Assembler* a, KModErr& out_err, GpX inode);

// 原型：void iput(struct inode *inode); 无返回值
void iput(Assembler* a, KModErr& out_err, GpX inode);

// 原型：void local_irq_save(uint64_t & out_flags); 无返回值
// 原型：void local_irq_restore(uint64_t flags); 无返回值
void local_irq_save(Assembler* a, GpX out_store_flags_reg);
void local_irq_restore(Assembler* a, GpX flags);

// 原型：int invalidate_inode_pages2(struct address_space *mapping); 返回值为 W0 寄存器
void invalidate_inode_pages2(Assembler* a, KModErr& out_err, GpX mapping);

} // namespace export_symbol
} // namespace kernel_module