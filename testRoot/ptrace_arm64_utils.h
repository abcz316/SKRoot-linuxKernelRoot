#ifndef PTRACE_ARM64_UTILS_H_
#define PTRACE_ARM64_UTILS_H_
#include <unistd.h>

#ifndef __aarch64__
#error "Not supported"  
#endif

#define pt_regs user_pt_regs    
#define uregs   regs  
#define ARM_pc  pc  
#define ARM_sp  sp  
#define ARM_cpsr    pstate  
#define ARM_lr      regs[30]  
#define ARM_r0      regs[0]    

#define CPSR_T_MASK     ( 1u << 5 )      
#define MAX_PATH 256

int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size);
/*
Func : 将size字节的data数据写入到pid进程的dest地址处
@param dest: 目的进程的栈地址
@param data: 需要写入的数据的起始地址
@param size: 需要写入的数据的大小，以字节为单位
*/
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);

int ptrace_getregs(pid_t pid, struct pt_regs * regs);

int ptrace_setregs(pid_t pid, struct pt_regs * regs);

int ptrace_continue(pid_t pid);
int ptrace_attach(pid_t pid);

int ptrace_detach(pid_t pid);

uint64_t ptrace_retval(struct pt_regs * regs);

uint64_t ptrace_ip(struct pt_regs * regs);
//总结一下ptrace_call_wrapper，它的完成两个功能：  
//一是调用ptrace_call函数来执行指定函数，执行完后将子进程挂起；  
//二是调用ptrace_getregs函数获取所有寄存器的值，主要是为了获取r0即函数的返回值。    
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, unsigned long * parameters, int param_num, struct pt_regs * regs);
/*
功能总结：
1，将要执行的指令写入寄存器中，指令长度大于4个long的话，需要将剩余的指令通过ptrace_writedata函数写入栈中；
2，使用ptrace_continue函数运行目的进程，直到目的进程返回状态值0xb7f（对该值的分析见后面红字）；
3，函数执行完之后，目标进程挂起，使用ptrace_getregs函数获取当前的所有寄存器值，方便后面使用ptrace_retval函数获取函数的返回值。
*/
int ptrace_call(pid_t pid, uintptr_t addr, unsigned long *params, int num_params, struct pt_regs* regs);

#endif /* PTRACE_ARM64_UTILS_H_ */
