#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

class IKallsymsLookup {
public:
    virtual ~IKallsymsLookup() = default;

    virtual bool init() = 0;
    virtual bool is_inited() const = 0;
    virtual uint64_t kallsyms_lookup_name(const char* name) = 0;
    virtual uint64_t kallsyms_symbol_size(uint64_t cur_addr) = 0;
    virtual std::unordered_map<std::string, uint64_t> kallsyms_on_each_symbol() = 0;
    virtual uint64_t get_kallsyms_relative_base() = 0;
};