 /**
  Copyright © 2018 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

  // symbolic constants for Linux/AArch64

  .equ BINSH,                0x0068732F6E69622F

  .equ BUFSIZ,               64
  .equ NULL,                  0
  .equ SIGCHLD,              17

  // sched.h
  .equ CSIGNAL,              0x000000FF // signal mask to be sent at exit
  .equ CLONE_VM,             0x00000100 // set if VM shared between processes
  .equ CLONE_FS,             0x00000200 // set if fs info shared between processes
  .equ CLONE_FILES,          0x00000400 // set if open files shared between processes
  .equ CLONE_SIGHAND,        0x00000800 // set if signal handlers and blocked signals shared
  .equ CLONE_PTRACE,         0x00002000 // set if we want to let tracing continue on the child too
  .equ CLONE_VFORK,          0x00004000 // set if the parent wants the child to wake it up on mm_release
  .equ CLONE_PARENT,         0x00008000 // set if we want to have the same parent as the cloner
  .equ CLONE_THREAD,         0x00010000 // Same thread group?
  .equ CLONE_NEWNS,          0x00020000 // New mount namespace group
  .equ CLONE_SYSVSEM,        0x00040000 // share system V SEM_UNDO semantics
  .equ CLONE_SETTLS,         0x00080000 // create a new TLS for the child
  .equ CLONE_PARENT_SETTID,  0x00100000 // set the TID in the parent
  .equ CLONE_CHILD_CLEARTID, 0x00200000 // clear the TID in the child
  .equ CLONE_DETACHED,       0x00400000 // Unused, ignored
  .equ CLONE_UNTRACED,       0x00800000 // set if the tracing process can't force CLONE_PTRACE
  .equ CLONE_CHILD_SETTID,   0x01000000 // set the TID in the child
  .equ CLONE_NEWCGROUP,      0x02000000 // New cgroup namespace
  .equ CLONE_NEWUTS,         0x04000000 // New utsname namespace
  .equ CLONE_NEWIPC,         0x08000000 // New ipc namespace
  .equ CLONE_NEWUSER,        0x10000000 // New user namespace
  .equ CLONE_NEWPID,         0x20000000 // New pid namespace
  .equ CLONE_NEWNET,         0x40000000 // New network namespace
  .equ CLONE_IO,             0x80000000 // Clone io context

  // fcntl.h
  .equ O_ACCMODE, 00000003
  .equ O_RDONLY,  00000000
  .equ O_WRONLY,  00000001
  .equ O_RDWR,    00000002
  .equ O_CREAT,   00000100
  .equ O_EXCL,    00000200
  .equ O_NOCTTY,  00000400
  .equ O_TRUNC,   00001000
  .equ O_APPEND,  00002000
  .equ O_NONBLOCK,00004000
  .equ O_CLOEXEC, 02000000

  .equ SHUT_RDWR,            2

  .equ STDIN_FILENO,         0
  .equ STDOUT_FILENO,        1
  .equ STDERR_FILENO,        2

  .equ AF_UNIX,              1
  .equ AF_INET,              2
  .equ SOCK_STREAM,          1
  .equ SOCK_DGRAM,           2
  .equ SOCK_CLOEXEC,   0x80000
  .equ IPPROTO_IP,           0

  // epoll.h
  .equ EPOLLIN,              0x001
  .equ EPOLLPRI,             0x002
  .equ EPOLLOUT,             0x004
  .equ EPOLLERR,             0x008
  .equ EPOLLHUP,             0x010
  .equ EPOLLRDNORM,          0x040
  .equ EPOLLRDBAND,          0x080
  .equ EPOLLWRNORM,          0x100
  .equ EPOLLWRBAND,          0x200
  .equ EPOLLMSG,             0x400

  .equ EPOLLEXCLUSIVE,       1 << 28
  .equ EPOLLWAKEUP,          1 << 29
  .equ EPOLLONESHOT,         1 << 30
  .equ EPOLLET,              1 << 31

  .equ EPOLL_CTL_ADD,        1
  .equ EPOLL_CTL_DEL,        2
  .equ EPOLL_CTL_MOD,        3

  // Linux/AArch64 system calls
  .equ SYS_epoll_create1,   20
  .equ SYS_epoll_ctl,       21
  .equ SYS_epoll_pwait,     22
  .equ SYS_dup3,            24
  .equ SYS_fcntl,           25
  .equ SYS_mount,           40
  .equ SYS_statfs,          43
  .equ SYS_faccessat,       48
  .equ SYS_chroot,          51
  .equ SYS_fchmodat,        53
  .equ SYS_openat,          56
  .equ SYS_close,           57
  .equ SYS_pipe2,           59
  .equ SYS_read,            63
  .equ SYS_write,           64
  .equ SYS_writev,          66
  .equ SYS_pselect6,        72
  .equ SYS_ppoll,           73
  .equ SYS_splice,          76
  .equ SYS_exit,            93
  .equ SYS_waitid,          95
  .equ SYS_unshare,         97
  .equ SYS_futex,           98
  .equ SYS_kill,           129
  .equ SYS_reboot,         142
  .equ SYS_setuid,         146
  .equ SYS_setsid,         157
  .equ SYS_uname,          160
  .equ SYS_clock_gettime,   113
  .equ SYS_getpid,         172
  .equ SYS_getppid,        173
  .equ SYS_getuid,         174
  .equ SYS_getgid,         176
  .equ SYS_gettid,         178
  .equ SYS_socket,         198
  .equ SYS_bind,           200
  .equ SYS_listen,         201
  .equ SYS_accept,         202
  .equ SYS_connect,        203
  .equ SYS_sendto,         206
  .equ SYS_recvfrom,       207
  .equ SYS_setsockopt,     208
  .equ SYS_getsockopt,     209
  .equ SYS_shutdown,       210
  .equ SYS_munmap,         215
  .equ SYS_clone,          220
  .equ SYS_execve,         221
  .equ SYS_mmap,           222
  .equ SYS_mprotect,       226
  .equ SYS_wait4,          260
  .equ SYS_getrandom,      278
  .equ SYS_memfd_create,   279
  .equ SYS_access,        1033
  .equ SYS_init_module,    105
  .equ SYS_lseek,           62
  .equ SYS_readlinkat,      78
  .equ SYS_finit_module,   273
  .equ SYS_ioctl,           29

  .equ EAGAIN,              11
  .equ SEEK_DATA,            3
  .equ MAP_SHARED,         0x1
  .equ MAP_PRIVATE,        0x2
  .equ PROT_READ,          0x1
  .equ PROT_WRITE,         0x2
  .equ PROT_EXEC,          0x4

  // mount.h (for the DEFEX bind-mount disguise in stage2)
  .equ MS_BIND,            4096
  .equ MS_REC,            16384
  .equ MS_PRIVATE,       262144

  // load a 64-bit immediate using MOV
  .macro movq Xn, imm
      movz    \Xn,  \imm & 0xFFFF
      movk    \Xn, (\imm >> 16) & 0xFFFF, lsl 16
      movk    \Xn, (\imm >> 32) & 0xFFFF, lsl 32
      movk    \Xn, (\imm >> 48) & 0xFFFF, lsl 48
  .endm

  // load a 32-bit immediate using MOV
  .macro movl Wn, imm
      movz    \Wn,  \imm & 0xFFFF
      movk    \Wn, (\imm >> 16) & 0xFFFF, lsl 16
  .endm

  // simulate a push operation
  .macro push Rn:req
      str     \Rn, [sp, -16]
  .endm

  // simulate a pop operation
  .macro pop R:req
      ldr     \Rn, [sp], 16
  .endm

// Save x0 to filename for debugging.
.macro debug filename
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    mov x26, x0

    mov x0, -100
    adr x1, \filename
    movl x2, (O_CREAT|O_EXCL|O_CLOEXEC|O_WRONLY)
    mov x3, (0777)
    mov x8, #SYS_openat
    svc 0

    mov x27, x0

    str x26, [sp, #-32]
    sub x1, sp, 32
    movl x2, 8
    mov x8, #SYS_write
    svc 0

    mov x0, x27
    mov x8, #SYS_close
    svc 0

    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
.endm

.macro create_mark filename
    mov x0, -100
    adr x1, \filename
    movl x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov x3, xzr
    mov x8, #SYS_openat
    svc 0
.endm
