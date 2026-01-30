#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace kernel_module {

enum class SymbolMatchMode : uint8_t {
    Exact,      // 完全匹配
    Prefix,     // 以 name 开头
    Suffix,     // 以 name 结尾
    Substring   // name 出现在任意位置
};
struct SymbolHit {
    uint64_t addr = 0;     // 符号地址
    char name[1024] = {0}; // 命中的符号名
};

/***************************************************************************
 * 根据符号名查找内核符号地址
 * 参数: name         要查找的内核符号名称（以 '\\0' 结尾的字符串）
 *       mode         符号匹配模式
 *       out          输出参数，返回找到的符号地址
 * 返回: OK 表示成功找到符号；其他值为错误码
 ***************************************************************************/
KModErr kallsyms_lookup_name(const char * name, SymbolMatchMode mode, SymbolHit & out);

inline KModErr kallsyms_lookup_name(const char * name, uint64_t & out) {
    SymbolHit hit = {0};
    KModErr err = kallsyms_lookup_name(name, SymbolMatchMode::Exact, hit);
    out = hit.addr;
    return err;
}

/***************************************************************************
 * 获取sys_call_table内核地址
 * 参数: func_start_addr             输出sys_call_table内核地址
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
inline KModErr get_sys_call_table_kaddr(uint64_t & kaddr) {
    return kallsyms_lookup_name("sys_call_table", kaddr);
}

/***************************************************************************
 * 获取指定系统调用号（NR）的内核函数地址（从 sys_call_table 读取）
 *
 * 参数: syscall_nr                 系统调用号（__NR_xxx）
 *      out_syscall_func_kaddr      输出 sys_call_table[syscall_nr] 中的函数指针地址
 *
 * 返回: OK 表示成功；其他值为错误码
 ***************************************************************************/
inline KModErr get_syscall_func_kaddr(int syscall_nr, uint64_t& out_syscall_func_kaddr) {
    uint64_t table_kaddr  = 0;
    RETURN_IF_ERROR(get_sys_call_table_kaddr(table_kaddr));
    return read_kernel_mem(table_kaddr + 8 * (uint64_t)syscall_nr, &out_syscall_func_kaddr, sizeof(out_syscall_func_kaddr));
}

/***************************************************************************
 * 判断系统调用参数是否通过 struct pt_regs 传递
 *
 * 返回 true：
 *   X0 为 struct pt_regs*，系统调用参数需从 pt_regs 中读取
 *
 * 返回 false：
 *   系统调用参数直接通过寄存器传递（X0=arg0, X1=arg1, ...）
 *
 * 适用于区分不同内核 syscall 参数传递方式
 ***************************************************************************/
bool is_syscall_args_in_ptregs();

/***************************************************************************
 * 获取avc_denied内核地址
 * 
 * 说明: 因部分手机内核对avc_denied有特殊保护，不可直接 Hook，Skroot在这里提供一个特殊内核地址，可绕过厂商的特殊保护。
 * 
 * 参数: func_entry_kaddr            输出 avc_denied 内核地址
 *      before_ret_can_hook_addr    输出 avc_denied return 前可安装HOOK的地址
 * 返回: OK 表示成功；其它值为错误码
 ***************************************************************************/
KModErr get_avc_denied_kaddr(uint64_t & func_entry_kaddr, uint64_t & before_ret_can_hook_kaddr);

}
