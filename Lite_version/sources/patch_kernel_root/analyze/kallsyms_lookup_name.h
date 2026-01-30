#pragma once
#include <iostream>
#include <cstdint>
#include <vector>
#include <unordered_map>

class KallsymsLookupName
{
public:
	KallsymsLookupName(const std::vector<char>& file_buf);
	~KallsymsLookupName();

public:
	bool init();
	bool is_inited();
	uint64_t kallsyms_lookup_name(const char* name);
	std::unordered_map<std::string, uint64_t> kallsyms_on_each_symbol();
	int get_kallsyms_num();

private:
	bool find_kallsyms_addresses_list(size_t& start, size_t& end);
	int find_kallsyms_num(size_t addresses_list_start, size_t addresses_list_end, size_t fuzzy_range, size_t& kallsyms_num_offset);
	bool find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end);
	bool find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end);
	bool find_kallsyms_token_table(size_t markers_list_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end);
	bool find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start);
	bool resolve_kallsyms_addresses_symbol_base(size_t code_static_start, uint64_t& base_address);

	unsigned int kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen);
	bool has_kallsyms_symbol(const char* name);

	const std::vector<char>& m_file_buf;
	int m_kallsyms_num = 0;
	bool m_inited = false;
	struct kallsyms_addresses_info {
		uint64_t base_address = 0;
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_addresses base_address: 0x" << base_address << std::endl;
			std::cout << std::hex << "kallsyms_addressess offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_addresses;

	struct kallsyms_names_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_names offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_names;

	struct kallsyms_markers_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_markers offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_markers;

	struct kallsyms_token_table_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_token_table offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_token_table;

	struct kallsyms_token_index_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_token_index offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_token_index;

	std::unordered_map<std::string, uint64_t> m_kallsyms_symbols_cache;
};