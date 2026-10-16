#pragma once
#include <link.h>
#include <stdint.h>
#include <string_view>
#include <vector>

class Elf {
    ElfW(Addr) base_addr_ = 0;
    ElfW(Addr) bias_addr_ = 0;

    ElfW(Ehdr) *header_ = nullptr;
    ElfW(Phdr) *program_header_ = nullptr;

    ElfW(Dyn) *dynamic_ = nullptr;  //.dynamic
    ElfW(Word) dynamic_size_ = 0;

    const char *dyn_str_ = nullptr;  //.dynstr (string-table)
    ElfW(Sym) *dyn_sym_ = nullptr;   //.dynsym (symbol-index to string-table's offset)

    ElfW(Addr) rel_plt_ = 0;  //.rel.plt or .rela.plt
    ElfW(Word) rel_plt_size_ = 0;

    ElfW(Addr) rel_dyn_ = 0;  //.rel.dyn or .rela.dyn
    ElfW(Word) rel_dyn_size_ = 0;

    ElfW(Addr) rel_android_ = 0;  // android compressed rel or rela
    ElfW(Word) rel_android_size_ = 0;

    // for ELF hash
    uint32_t *bucket_ = nullptr;
    uint32_t bucket_count_ = 0;
    uint32_t *chain_ = nullptr;

    // append for GNU hash
    uint32_t sym_offset_ = 0;
    ElfW(Addr) *bloom_ = nullptr;
    uint32_t bloom_size_ = 0;
    uint32_t bloom_shift_ = 0;

    bool is_use_rela_ = false;
    bool valid_ = false;

    uint32_t GnuLookup(std::string_view name) const;
    uint32_t ElfLookup(std::string_view name) const;
    uint32_t LinearLookup(std::string_view name) const;
public:
    std::vector<uintptr_t> FindPltAddr(std::string_view name) const;
    Elf(uintptr_t base_addr);
    bool Valid() const { return valid_; };
};
