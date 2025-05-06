#pragma once
#include <iostream>
#include <vector>
class KallsymsLookupName_6_1_42
{
public:
	KallsymsLookupName_6_1_42(const std::vector<char>& file_buf);
	~KallsymsLookupName_6_1_42();

public:
	bool init();
	bool is_inited();
	uint64_t kallsyms_lookup_name(const char* name, bool include_str_mode = false);
	int get_kallsyms_num();

private:
	bool find_kallsyms_offsets_list(size_t& start, size_t& end);
	uint64_t find_kallsyms_relative_base(size_t offset_list_end, size_t& kallsyms_relative_base_offset);
	int find_kallsyms_num(size_t offset_list_start, size_t offset_list_end, size_t kallsyms_relative_base_end_offset, size_t& kallsyms_num_offset);
	bool find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end);
	bool find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end, bool & markers_list_is_align8);
	bool find_kallsyms_seqs_of_names_list(int kallsyms_num, size_t markers_list_end_offset, bool markers_list_is_align8, size_t& seqs_of_names_list_start, size_t& seqs_of_names_list_end);
	bool find_kallsyms_token_table(size_t seqs_of_names_list_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end);
	bool find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start);
	bool find_kallsyms_sym_func_entry_offset(size_t& kallsyms_sym_func_entry_offset);

	unsigned int kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen);
	uint64_t __kallsyms_lookup_name(const char* name, bool include_str_mode = false);
	int kallsyms_lookup_names(const char* name, unsigned int* start, unsigned int* end);
	unsigned int get_symbol_offset(unsigned long pos);
	uint64_t kallsyms_sym_address(int idx);
	int compare_symbol_name(const char* name, char* namebuf);
	bool cleanup_symbol_name(char* s);

	const std::vector<char>& m_file_buf;
	uint64_t m_kallsyms_relative_base = 0;
	int m_kallsyms_num = 0;
	bool m_inited = false;
	size_t m_kallsyms_sym_func_entry_offset = 0;

	struct kallsyms_offsets_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_offsets offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_offsets;

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

	struct kallsyms_seqs_of_names_info {
		size_t offset = 0;
		void printf() {
			std::cout << std::hex << "kallsyms_seqs_of_names offset: 0x" << offset << std::endl;
		}
	} m_kallsyms_seqs_of_names;

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
};