#pragma once
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <iostream>
#include <sys/mman.h>
#include <map>
#include <vector>
#include <errno.h>

#include "rootkit_err_def.h"
namespace kernel_root {
	
struct dl_iterate_callback_data {
    const char *target_so_name;
    std::shared_ptr<std::map<std::string, uint64_t>> sp_func_symbol_map;
};


static bool is_elf64_file(int fd) {
	Elf64_Ehdr elf;
	int r = read(fd, &elf, sizeof(elf));
	if (r != sizeof(elf)) {
		return false;
	}
	if (*(uint32_t*)&elf != 0x464c457f) {
		//not an ELF file
		return false;
	}
	unsigned char* b = (unsigned char*)&elf;
	if (b[EI_CLASS] == ELFCLASS64) {
		return true;
	}
	return false;
}

static KRootErr read_elf64_file_symbol_addr(const char* so_path, std::map<std::string, uint64_t>& func_symbol_map) {
	int fd;
	char* mod;
	unsigned int size, i, j, shn, n;
	Elf64_Sym* syms, * sym;
	Elf64_Shdr* shdrs, * shdr;
	Elf64_Ehdr* ehdr;
	const char* strtab;

	fd = open(so_path, O_RDONLY);
	if (fd < 0) {
		return KRootErr::ERR_OPEN_FILE;
	}
	lseek(fd, 0L, SEEK_SET);
	if (!is_elf64_file(fd)) {
		close(fd);
		return KRootErr::ERR_NOT_ELF64_FILE;
	}
	size = lseek(fd, 0L, SEEK_END);
	mod = (char*)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

	ehdr = (Elf64_Ehdr*)mod;
	shdrs = (Elf64_Shdr*)(mod + ehdr->e_shoff);
	shn = ehdr->e_shnum == 0 ? shdrs[0].sh_size : ehdr->e_shnum;

	for (i = 0; i < shn; i++) {
		shdr = &shdrs[i];

		if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
			syms = (Elf64_Sym*)(mod + shdr->sh_offset);
			strtab = mod + shdrs[shdr->sh_link].sh_offset;
			n = shdr->sh_size / shdr->sh_entsize;
			for (j = 0; j < n; j++) {
				char stype, sbind, sinfo;

				sym = &syms[j];
				stype = ELF64_ST_TYPE(sym->st_info);
				sbind = ELF32_ST_BIND(sym->st_info);
				sinfo = ELF32_ST_INFO(sbind, stype);
				if (stype == STT_FUNC && sbind == STB_GLOBAL &&
					sym->st_other == STV_DEFAULT &&
					(uintmax_t)sym->st_size > 0) {
					
					auto iter = func_symbol_map.find(strtab + sym->st_name);
					if (iter == func_symbol_map.end()) {
						continue;
					}
					iter->second = sym->st_value;
				}
			}
		}
	}
	munmap(mod, size);
	close(fd);
	return KRootErr::OK;
}

KRootErr find_mem_elf64_symbol_address(const char *so_path, std::map<std::string, uint64_t>& func_symbol_map) {
    void* p_so_addr = get_module_base(-1, so_path);
	void* p_so = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
	if (!p_so || !p_so_addr) {
		return KRootErr::ERR_DLOPEN_FILE;
	}
	for(auto iter = func_symbol_map.begin(); iter != func_symbol_map.end(); iter++) {
		void* pfunc = dlsym(p_so, iter->first.c_str());
		if(pfunc) {
			iter->second = ((size_t)pfunc - (size_t)p_so_addr);
		}
	}
	dlclose(p_so);
	return KRootErr::OK;
}

}