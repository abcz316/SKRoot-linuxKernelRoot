#include "elf_util.hpp"

#include <cstring>
#include <type_traits>
#include <vector>
#include <tuple>

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    //.rel.dyn
#define ELF_R_GENERIC_ABS R_ARM_ABS32            //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_X86_64_64
#elif defined(__riscv)
#define ELF_R_GENERIC_JUMP_SLOT R_RISCV_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_RISCV_64
#define ELF_R_GENERIC_ABS R_RISCV_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

namespace {
template <typename T>
inline constexpr auto OffsetOf(ElfW(Ehdr) * head, ElfW(Off) off) {
    return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T *>>(
        reinterpret_cast<uintptr_t>(head) + off);
}

template <typename T>
inline constexpr auto SetByOffset(T &ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
    if (auto val = bias + off; val > base) {
        ptr = reinterpret_cast<T>(val);
        return true;
    }
    ptr = 0;
    return false;
}

}  // namespace

Elf::Elf(uintptr_t base_addr) : base_addr_(base_addr) {
    header_ = reinterpret_cast<decltype(header_)>(base_addr);

    // check magic
    if (0 != memcmp(header_->e_ident, ELFMAG, SELFMAG)) return;

        // check class (64/32)
#if defined(__LP64__)
    if (ELFCLASS64 != header_->e_ident[EI_CLASS]) return;
#else
    if (ELFCLASS32 != header_->e_ident[EI_CLASS]) return;
#endif

    // check endian (little/big)
    if (ELFDATA2LSB != header_->e_ident[EI_DATA]) return;

    // check version
    if (EV_CURRENT != header_->e_ident[EI_VERSION]) return;

    // check type
    if (ET_EXEC != header_->e_type && ET_DYN != header_->e_type) return;

        // check machine
#if defined(__arm__)
    if (EM_ARM != header_->e_machine) return;
#elif defined(__aarch64__)
    if (EM_AARCH64 != header_->e_machine) return;
#elif defined(__i386__)
    if (EM_386 != header_->e_machine) return;
#elif defined(__x86_64__)
    if (EM_X86_64 != header_->e_machine) return;
#elif defined(__riscv)
    if (EM_RISCV != header_->e_machine) return;
#else
    return;
#endif

    // check version
    if (EV_CURRENT != header_->e_version) return;

    program_header_ = OffsetOf<decltype(program_header_)>(header_, header_->e_phoff);

    auto ph_off = reinterpret_cast<uintptr_t>(program_header_);
    for (int i = 0; i < header_->e_phnum; i++, ph_off += header_->e_phentsize) {
        auto *program_header = reinterpret_cast<ElfW(Phdr) *>(ph_off);
        if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
            if (base_addr_ >= program_header->p_vaddr) {
                bias_addr_ = base_addr_ - program_header->p_vaddr;
            }
        } else if (program_header->p_type == PT_DYNAMIC) {
            dynamic_ = reinterpret_cast<decltype(dynamic_)>(program_header->p_vaddr);
            dynamic_size_ = program_header->p_memsz;
        }
    }
    if (!dynamic_ || !bias_addr_) return;
    dynamic_ =
        reinterpret_cast<decltype(dynamic_)>(bias_addr_ + reinterpret_cast<uintptr_t>(dynamic_));

    for (auto *dynamic = dynamic_, *dynamic_end = dynamic_ + (dynamic_size_ / sizeof(dynamic[0]));
         dynamic < dynamic_end; ++dynamic) {
        switch (dynamic->d_tag) {
        case DT_NULL:
            // the end of the dynamic-section
            dynamic = dynamic_end;
            break;
        case DT_STRTAB: {
            if (!SetByOffset(dyn_str_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_SYMTAB: {
            if (!SetByOffset(dyn_sym_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTREL:
            // use rel or rela?
            is_use_rela_ = dynamic->d_un.d_val == DT_RELA;
            break;
        case DT_JMPREL: {
            if (!SetByOffset(rel_plt_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTRELSZ:
            rel_plt_size_ = dynamic->d_un.d_val;
            break;
        case DT_REL:
        case DT_RELA: {
            if (!SetByOffset(rel_dyn_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_RELSZ:
        case DT_RELASZ:
            rel_dyn_size_ = dynamic->d_un.d_val;
            break;
        case DT_ANDROID_REL:
        case DT_ANDROID_RELA: {
            if (!SetByOffset(rel_android_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_ANDROID_RELSZ:
        case DT_ANDROID_RELASZ:
            rel_android_size_ = dynamic->d_un.d_val;
            break;
        case DT_HASH: {
            // ignore DT_HASH when ELF contains DT_GNU_HASH hash table
            if (bloom_) continue;
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            bucket_ = raw + 2;
            chain_ = bucket_ + bucket_count_;
            break;
        }
        case DT_GNU_HASH: {
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            sym_offset_ = raw[1];
            bloom_size_ = raw[2];
            bloom_shift_ = raw[3];
            bloom_ = reinterpret_cast<decltype(bloom_)>(raw + 4);
            bucket_ = reinterpret_cast<decltype(bucket_)>(bloom_ + bloom_size_);
            chain_ = bucket_ + bucket_count_ - sym_offset_;
            //            is_use_gnu_hash_ = true;
            break;
        }
        default:
            break;
        }
    }

    // check android rel/rela
    if (0 != rel_android_) {
        const auto *rel = reinterpret_cast<const char *>(rel_android_);
        if (rel_android_size_ < 4 || rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' ||
            rel[3] != '2') {
            return;
        }

        rel_android_ += 4;
        rel_android_size_ -= 4;
    }

    valid_ = true;
}

uint32_t Elf::GnuLookup(std::string_view name) const {
    static constexpr auto kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
    static constexpr uint32_t kInitialHash = 5381;
    static constexpr uint32_t kHashShift = 5;

    if (!bucket_ || !bloom_) return 0;

    uint32_t hash = kInitialHash;
    for (unsigned char chr : name) {
        hash += (hash << kHashShift) + chr;
    }

    auto bloom_word = bloom_[(hash / kBloomMaskBits) % bloom_size_];
    uintptr_t mask = 0 | uintptr_t{1} << (hash % kBloomMaskBits) |
                     uintptr_t{1} << ((hash >> bloom_shift_) % kBloomMaskBits);
    if ((mask & bloom_word) == mask) {
        auto idx = bucket_[hash % bucket_count_];
        if (idx >= sym_offset_) {
            const char *strings = dyn_str_;
            do {
                auto *sym = dyn_sym_ + idx;
                if (((chain_[idx] ^ hash) >> 1) == 0 && name == strings + sym->st_name) {
                    return idx;
                }
            } while ((chain_[idx++] & 1) == 0);
        }
    }
    return 0;
}

uint32_t Elf::ElfLookup(std::string_view name) const {
    static constexpr uint32_t kHashMask = 0xf0000000;
    static constexpr uint32_t kHashShift = 24;
    uint32_t hash = 0;
    uint32_t tmp;

    if (!bucket_ || bloom_) return 0;

    for (unsigned char chr : name) {
        hash = (hash << 4) + chr;
        tmp = hash & kHashMask;
        hash ^= tmp;
        hash ^= tmp >> kHashShift;
    }
    const char *strings = dyn_str_;

    for (auto idx = bucket_[hash % bucket_count_]; idx != 0; idx = chain_[idx]) {
        auto *sym = dyn_sym_ + idx;
        if (name == strings + sym->st_name) {
            return idx;
        }
    }
    return 0;
}

uint32_t Elf::LinearLookup(std::string_view name) const {
    if (!dyn_sym_ || !sym_offset_) return 0;
    for (uint32_t idx = 0; idx < sym_offset_; idx++) {
        auto *sym = dyn_sym_ + idx;
        if (name == dyn_str_ + sym->st_name) {
            return idx;
        }
    }
    return 0;
}

std::vector<uintptr_t> Elf::FindPltAddr(std::string_view name) const {
    std::vector<uintptr_t> res;

    uint32_t idx = GnuLookup(name);
    if (!idx) idx = ElfLookup(name);
    if (!idx) idx = LinearLookup(name);
    if (!idx) return res;

    auto looper = [&]<typename T>(auto begin, auto size, bool is_plt) -> void {
        const auto *rel_end = reinterpret_cast<const T *>(begin + size);
        for (const auto *rel = reinterpret_cast<const T *>(begin); rel < rel_end; ++rel) {
            auto r_info = rel->r_info;
            auto r_offset = rel->r_offset;
            auto r_sym = ELF_R_SYM(r_info);
            auto r_type = ELF_R_TYPE(r_info);
            if (r_sym != idx) continue;
            if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
            if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) {
                continue;
            }
            auto addr = bias_addr_ + r_offset;
            if (addr > base_addr_) res.emplace_back(addr);
            if (is_plt) break;
        }
    };

    for (const auto &[rel, rel_size, is_plt] :
         {std::make_tuple(rel_plt_, rel_plt_size_, true),
          std::make_tuple(rel_dyn_, rel_dyn_size_, false),
          std::make_tuple(rel_android_, rel_android_size_, false)}) {
        if (!rel) continue;
        if (is_use_rela_) {
            looper.template operator()<ElfW(Rela)>(rel, rel_size, is_plt);
        } else {
            looper.template operator()<ElfW(Rel)>(rel, rel_size, is_plt);
        }
    }

    return res;
}
