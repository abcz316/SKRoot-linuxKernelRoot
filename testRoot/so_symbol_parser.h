#ifndef SO_SYMBOL_PARSER_H_
#define SO_SYMBOL_PARSER_H_
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <map>
#include <vector>
#include <errno.h>

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

static int get_so_symbol_addr(const char* so_path, std::map<std::string, uint64_t>& funcSymbolMap) {
	int fd;
	char* mod;
	unsigned int size, i, j, shn, n;
	Elf64_Sym* syms, * sym;
	Elf64_Shdr* shdrs, * shdr;
	Elf64_Ehdr* ehdr;
	const char* strtab;

	fd = open(so_path, O_RDONLY);
	if (fd < 0) {
		return -2000001;
	}
	lseek(fd, 0L, SEEK_SET);
	if (!is_elf64_file(fd)) {
		close(fd);
		return -2000002;
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

					if (funcSymbolMap.find(strtab + sym->st_name) == funcSymbolMap.end()) {
						continue;
					}
					funcSymbolMap[strtab + sym->st_name] = sym->st_value;
				}
			}
		}
	}
	munmap(mod, size);
	close(fd);
	return 0;
}
#endif /* SO_SYMBOL_PARSER_H_ */
