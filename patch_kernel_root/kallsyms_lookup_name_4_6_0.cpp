#pragma once
#include "kallsyms_lookup_name_4_6_0.h"
#include "base_func.h"

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

#define MAX_FIND_RANGE 0x1000
namespace {
	const int KSYM_NAME_LEN = 128;
}
KallsymsLookupName_4_6_0::KallsymsLookupName_4_6_0(const std::vector<char>& file_buf) : m_file_buf(file_buf)
{
}

KallsymsLookupName_4_6_0::~KallsymsLookupName_4_6_0()
{
}

bool KallsymsLookupName_4_6_0::init() {
	size_t offset_list_start = 0, offset_list_end = 0;
	if (!find_kallsyms_offsets_list(offset_list_start, offset_list_end)) {
		std::cout << "Unable to find the list of kallsyms offsets" << std::endl;
		return false;
	}
	size_t kallsyms_num_offset = 0;
	m_kallsyms_num = find_kallsyms_num(offset_list_start, offset_list_end, kallsyms_num_offset);
	if (!m_kallsyms_num) {
		std::cout << "Unable to find the num of kallsyms offset list" << std::endl;
		return false;
	}

	std::cout << std::hex << "kallsyms_num: 0x" << m_kallsyms_num << std::endl;

	// revise the offset list offset again
	const int offset_list_var_len = sizeof(long);
	offset_list_start = offset_list_end - m_kallsyms_num * offset_list_var_len;
	long test_first_offset_list_val;
	do {
		test_first_offset_list_val = *(long*)&m_file_buf[offset_list_start];
		if (test_first_offset_list_val) {
			offset_list_start -= offset_list_var_len;
			offset_list_end -= offset_list_var_len;
		}
	} while (test_first_offset_list_val);

	std::cout << std::hex << "kallsyms_offset_start: 0x" << offset_list_start << std::endl;
	std::cout << std::hex << "kallsyms_offset_end: 0x" << offset_list_end << std::endl;
	m_kallsyms_offsets.offset = offset_list_start;

	size_t kallsyms_num_end_offset = kallsyms_num_offset + sizeof(m_kallsyms_num);
	size_t name_list_start = 0, name_list_end = 0;
	if (!find_kallsyms_names_list(m_kallsyms_num, kallsyms_num_end_offset, name_list_start, name_list_end)) {
		std::cout << "Unable to find the list of kallsyms names list" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_names_start: 0x" << name_list_start << std::endl;
	std::cout << std::hex << "kallsyms_names_end: 0x" << name_list_end << std::endl;
	m_kallsyms_names.offset = name_list_start;

	size_t markers_list_start = 0;
	size_t markers_list_end = 0;
	if (!find_kallsyms_markers_list(m_kallsyms_num, name_list_end, markers_list_start, markers_list_end)) {
		std::cout << "Unable to find the list of kallsyms markers list" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_markers_start: 0x" << markers_list_start << std::endl;
	std::cout << std::hex << "kallsyms_markers_end: 0x" << markers_list_end << std::endl;
	m_kallsyms_markers.offset = markers_list_start;

	size_t token_table_start = 0;
	size_t token_table_end = 0;
	if (!find_kallsyms_token_table(markers_list_end, token_table_start, token_table_end)) {
		std::cout << "Unable to find the list of kallsyms token table" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_token_table_start: 0x" << token_table_start << std::endl;
	std::cout << std::hex << "kallsyms_token_table_end: 0x" << token_table_end << std::endl;
	m_kallsyms_token_table.offset = token_table_start;

	size_t token_index_start = 0;
	if (!find_kallsyms_token_index(token_table_end, token_index_start)) {
		std::cout << "Unable to find the list of kallsyms token index" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_token_index_start: 0x" << token_index_start << std::endl;
	m_kallsyms_token_index.offset = token_index_start;
	
	size_t kallsyms_sym_func_entry_offset = 0;
	if (!find_kallsyms_sym_func_entry_offset(kallsyms_sym_func_entry_offset)) {
		std::cout << "Unable to find the list of kallsyms sym function entry offset" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_sym_func_entry_offset: 0x" << kallsyms_sym_func_entry_offset << std::endl;
	m_kallsyms_sym_func_entry_offset = kallsyms_sym_func_entry_offset;
	
	m_inited = true;
	return true;
}

bool KallsymsLookupName_4_6_0::is_inited() {
	return m_inited;
}

int KallsymsLookupName_4_6_0::get_kallsyms_num() {
	return m_kallsyms_num;
}
bool KallsymsLookupName_4_6_0::find_kallsyms_offsets_list(size_t& start, size_t& end) {
	const int var_len = sizeof(long);
	for (auto x = 0; x + var_len < m_file_buf.size(); x += var_len) {
		long val1 = *(long*)&m_file_buf[x];
		long val2 = *(long*)&m_file_buf[x + var_len];
		if (val1 != 0 || val1 >= val2) {
			continue;
		}
		int cnt = 0;
		auto j = x + var_len;
		for (; j + var_len < m_file_buf.size(); j += var_len) {
			val1 = *(long*)&m_file_buf[j];
			val2 = *(long*)&m_file_buf[j + var_len];
			if (val1 > val2 || val2 == 0 || (val2 - val1) > 0x1000000) {
				j += var_len;
				break;
			}
			cnt++;
		}
		if (cnt >= 0x10000) {
			start = x;
			end = j;
			return true;
		}
	}
	return false;
}

int KallsymsLookupName_4_6_0::find_kallsyms_num(size_t offset_list_start, size_t offset_list_end, size_t& kallsyms_num_offset) {
	size_t size = (offset_list_end - offset_list_start) / sizeof(int);
	size_t allow_min_size = size - 10;
	size_t allow_max_size = size + 10;
	auto _min = MIN(m_file_buf.size(), MAX_FIND_RANGE);
	int cnt = 10;
	for (size_t x = 0; (x + sizeof(int)) < _min; x++) {
		auto pos = offset_list_end + x * sizeof(int);
		int val = *(int*)&m_file_buf[pos];
		if (val == 0) {
			continue;
		}
		if (val >= allow_min_size && val < allow_max_size) {
			kallsyms_num_offset = pos;
			return val;
		}
		if (--cnt == 0) {
			break;
		}
	}
	return 0;
}


bool KallsymsLookupName_4_6_0::find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end) {

	name_list_start = 0;
	name_list_end = 0;
	size_t x = kallsyms_num_end_offset;
	auto _min = MIN(m_file_buf.size(), x + MAX_FIND_RANGE);
	for (; (x + sizeof(char)) < _min; x++) {
		char val = *(char*)&m_file_buf[x];
		if (val == '\0') {
			continue;
		}
		name_list_start = x;
		break;
	}
	size_t off = name_list_start;
	for (int i = 0; i < kallsyms_num; i++) {
		unsigned char ch = (unsigned char)m_file_buf[off++];
		off += ch;
	}
	name_list_end = off;
	return true;
}


bool KallsymsLookupName_4_6_0::find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end) {
	size_t start = align8(name_list_end_offset);
	const int var_len = sizeof(long);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		long val1 = *(long*)&m_file_buf[x];
		long val2 = *(long*)&m_file_buf[x + var_len];
		if (val1 == 0 && val2 > 0) {
			markers_list_start = x;
			break;
		} else if (val1 == 0 && val2 == 0) {
			continue;
		}
		return false;
	}
	
	auto exist_val_start = markers_list_start + var_len;

	bool is_align8 = false;
	int cnt = 5;
	long last_second_var_val = 0;
	for (auto y = markers_list_start + var_len; y + var_len < m_file_buf.size(); y += var_len * 2) {
		long val1 = *(long*)&m_file_buf[y];
		long val2 = *(long*)&m_file_buf[y + var_len];
		if (val2 != last_second_var_val) {
			break;
		}
		last_second_var_val = val2;
		cnt--;
		if (cnt == 0) {
			is_align8 = true;
			break;
		}
	}
	if (is_align8) {
		size_t back_val = align8(markers_list_start) - markers_list_start;
		if (back_val == 0) {
			markers_list_start -= 8;
		} else {
			markers_list_start -= back_val; // 4
		}
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(long) * 2;
	} else {
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(long);
	}
	
	return true;
}

bool KallsymsLookupName_4_6_0::find_kallsyms_token_table(size_t markers_list_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end) {
	size_t start = align8(markers_list_end_offset);
	const int var_len = sizeof(long);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		long val1 = *(long*)&m_file_buf[x];
		if (val1 == 0) {
			continue;
		}
		size_t off = x;
		for (unsigned int i = 0; i < 256; i++) {
			const char* str = (const char*)&m_file_buf[off];
			off += strlen(str) + 1;
		}
		kallsyms_token_table_start = x;
		kallsyms_token_table_end = off;
		return true;
	}
	return false;
}

bool KallsymsLookupName_4_6_0::find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start) {
	size_t start = align8(kallsyms_token_table_end);
	const int var_len = sizeof(short);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		short val1 = *(short*)&m_file_buf[x];
		short val2 = *(short*)&m_file_buf[x + var_len];
		if (val1 == 0 && val2 > 0) {
			kallsyms_token_index_start = x;
			break;
		}
		else if (val1 == 0 && val2 == 0) {
			continue;
		}
		return false;
	}
	return true;
}

bool KallsymsLookupName_4_6_0::find_kallsyms_sym_func_entry_offset(size_t& kallsyms_sym_func_entry_offset) {
	size_t _text_offset = __kallsyms_lookup_name("_text");
	size_t _stext_offset = __kallsyms_lookup_name("_stext");
	if (_text_offset != 0) {
		return false;
	}
	const int var_len = sizeof(int);
	for (auto x = _stext_offset; x + var_len < m_file_buf.size(); x += var_len) {
		int val1 = *(int*)&m_file_buf[x];
		if (val1 == 0 ) {
			continue;
		}
		kallsyms_sym_func_entry_offset = x - _stext_offset;
		break;
	}
	return true;
}

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * if uncompressed string is too long (>= maxlen), it will be truncated,
 * given the offset to where the symbol is in the compressed stream.
 */
unsigned int KallsymsLookupName_4_6_0::kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen)
{
	int len, skipped_first = 0;
	const char* tptr;
	const uint8_t* data;

	/* Get the compressed symbol length from the first symbol byte. */

	data = (uint8_t*)&m_file_buf[m_kallsyms_names.offset + off * sizeof(uint8_t)];

	len = *data;
	data++;

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len + 1;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */

	while (len) {
		uint8_t x = *data;
		short y = *(short*)&m_file_buf[m_kallsyms_token_index.offset + x * sizeof(uint16_t)];

		tptr = &m_file_buf[m_kallsyms_token_table.offset + y * sizeof(unsigned char)];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				if (maxlen <= 1)
					goto tail;
				*result = *tptr;
				result++;
				maxlen--;
			}
			else
				skipped_first = 1;
			tptr++;
		}
	}

tail:
	if (maxlen)
		*result = '\0';

	/* Return to offset to the next symbol. */
	return off;
}

/* Lookup the address for this symbol. Returns 0 if not found. */
uint64_t KallsymsLookupName_4_6_0::__kallsyms_lookup_name(const char* name, bool include_str_mode) {
	for (auto i = 0, off = 0; i < m_kallsyms_num; i++) {
		char namebuf[KSYM_NAME_LEN] = { 0 };
		off = kallsyms_expand_symbol(off, namebuf, sizeof(namebuf));

		if (strcmp(namebuf, name) == 0 || (include_str_mode && strstr(namebuf, name))) {
			auto pos = m_kallsyms_offsets.offset + i * sizeof(int);
			uint64_t offset = *(long*)&m_file_buf[pos];
			offset += m_kallsyms_sym_func_entry_offset;
			return offset;
		}
	}
	return 0;
}

uint64_t KallsymsLookupName_4_6_0::kallsyms_lookup_name(const char* name, bool include_str_mode) {
	if (!m_inited) { return 0;  }
	return __kallsyms_lookup_name(name, include_str_mode);
}
