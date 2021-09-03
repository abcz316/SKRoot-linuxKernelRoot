#include "ptrace_arm64_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <elf.h>
#include <sys/uio.h>
#include <cinttypes>

int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size)
{
	long i, j, remain;
	uint8_t *laddr;
	size_t bytes_width = sizeof(long);

	union u {
		long val;
		char chars[sizeof(val)];
	} d;

	j = size / bytes_width;
	remain = size % bytes_width;

	laddr = buf;

	for (i = 0; i < j; i++) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, bytes_width);
		src += bytes_width;
		laddr += bytes_width;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, remain);
	}

	return 0;
}

/*
Func : 将size字节的data数据写入到pid进程的dest地址处
@param dest: 目的进程的栈地址
@param data: 需要写入的数据的起始地址
@param size: 需要写入的数据的大小，以字节为单位
*/
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
	long i, j, remain;
	uint8_t *laddr;
	size_t bytes_width = sizeof(long);

	//很巧妙的联合体，这样就可以方便的以字节为单位写入4字节数据，再以long为单位ptrace_poketext到栈中    
	union u {
		long val;
		char chars[sizeof(val)];
	} d;

	j = size / bytes_width;
	remain = size % bytes_width;

	laddr = data;

	//先以4字节为单位进行数据写入  

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, bytes_width);
		ptrace(PTRACE_POKETEXT, pid, dest, d.val);

		dest += bytes_width;
		laddr += bytes_width;
	}

	if (remain > 0) {
		//为了最大程度的保持原栈的数据，先读取dest的long数据，然后只更改其中的前remain字节，再写回  
		d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, dest, d.val);
	}

	return 0;
}


int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
	int regset = NT_PRSTATUS;
	struct iovec ioVec;

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	if (ptrace(PTRACE_GETREGSET, pid, (size_t)regset, &ioVec) < 0) {
		perror("ptrace_getregs: Can not get register values");
		TRACE(" io %p, %lu", ioVec.iov_base, ioVec.iov_len);
		return -1;
	}
	return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
	int regset = NT_PRSTATUS;
	struct iovec ioVec;

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	if (ptrace(PTRACE_SETREGSET, pid, (size_t)regset, &ioVec) < 0) {
		perror("ptrace_setregs: Can not get register values");
		return -1;
	}
	return 0;
}

int ptrace_continue(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		perror("ptrace_attach");
		return -1;
	}

	int status = 0;
	waitpid(pid, &status, WUNTRACED);

	return 0;
}

int ptrace_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
		perror("ptrace_detach");
		return -1;
	}

	return 0;
}

uint64_t ptrace_retval(struct pt_regs * regs)
{
	return regs->ARM_r0;
}

uint64_t ptrace_ip(struct pt_regs * regs)
{
	return regs->ARM_pc;
}

//总结一下ptrace_call_wrapper，它的完成两个功能：  
//一是调用ptrace_call函数来执行指定函数，执行完后将子进程挂起；  
//二是调用ptrace_getregs函数获取所有寄存器的值，主要是为了获取r0即函数的返回值。    
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, unsigned long * parameters, int param_num, struct pt_regs * regs)
{
	TRACE("[+] Calling %s in target process.\n", func_name);
	if (ptrace_call(target_pid, (uintptr_t)func_addr, parameters, param_num, regs) == -1)
		return -1;

	if (ptrace_getregs(target_pid, regs) == -1)
		return -1;
	TRACE("[+] Target process returned from %s, return value=%" PRIu64 ", pc=%" PRIu64 " \n",
		func_name, ptrace_retval(regs), ptrace_ip(regs));
	return 0;
}

/*
功能总结：
1，将要执行的指令写入寄存器中，指令长度大于4个long的话，需要将剩余的指令通过ptrace_writedata函数写入栈中；
2，使用ptrace_continue函数运行目的进程，直到目的进程返回状态值0xb7f（对该值的分析见后面红字）；
3，函数执行完之后，目标进程挂起，使用ptrace_getregs函数获取当前的所有寄存器值，方便后面使用ptrace_retval函数获取函数的返回值。
*/
int ptrace_call(pid_t pid, uintptr_t addr, unsigned long *params, int num_params, struct pt_regs* regs)
{
	int i;
	int num_param_registers = 8; //aarch64
	for (i = 0; i < num_params && i < num_param_registers; i++) {
		regs->uregs[i] = params[i];
	}

	//      
	// push remained params onto stack      
	//      
	if (i < num_params) {
		regs->ARM_sp -= (num_params - i) * sizeof(long);
		ptrace_writedata(pid, (uint8_t *)regs->ARM_sp, (uint8_t *)& params[i], (num_params - i) * sizeof(long));
	}
	//将PC寄存器值设为目标函数的地址  
	regs->ARM_pc = addr;
	//进行指令集判断   
	if (regs->ARM_pc & 1) {
		/* thumb */
		regs->ARM_pc &= (~1u);
		// #define CPSR_T_MASK  ( 1u << 5 )  CPSR为程序状态寄存器  
		regs->ARM_cpsr |= CPSR_T_MASK;
	}
	else {
		/* arm */
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	//设置子程序的返回地址为空，以便函数执行完后，返回到null地址，产生SIGSEGV错误，详细作用见后面的红字分析  
	regs->ARM_lr = 0;

	/*
	*Ptrace_setregs就是将修改后的regs写入寄存器中，然后调用ptrace_continue来执行我们指定的代码
	*/
	if (ptrace_setregs(pid, regs) == -1
		|| ptrace_continue(pid) == -1) {
		TRACE("error\n");
		return -1;
	}

	int stat = 0;
	waitpid(pid, &stat, WUNTRACED);
	/* WUNTRACED告诉waitpid，如果子进程进入暂停状态，那么就立即返回。如果是被ptrace的子进程，那么即使不提供WUNTRACED参数，也会在子进程进入暂停状态的时候立即返回。
	对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。这里的0xb7f就表示子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV)，它表示试图访问未分配给自己的内存, 或试图往没有写权限的内存地址写数据。那么什么时候会发生这种错误呢？显然，当子进程执行完注入的函数后，由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV了！*/

	//这个循环是否必须我还不确定。因为目前每次ptrace_call调用必定会返回0xb7f，不过在这也算是增加容错性吧~  

	//通过看ndk的源码sys/wait.h以及man waitpid可以知道这个0xb7f的具体作用。首先说一下stat的值：高2字节用于表示导致子进程的退出或暂停状态信号值，低2字节表示子进程是退出(0x0)还是暂停(0x7f)状态。0xb7f就表示子进程为暂停状态，导致它暂停的信号量为11即sigsegv错误。  
	while (stat != 0xb7f) {
		if (ptrace_continue(pid) == -1) {
			TRACE("error\n");
			return -1;
		}
		waitpid(pid, &stat, WUNTRACED);
	}

	return 0;
}

