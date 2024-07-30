#pragma once
#include "kallsyms_lookup_name_6_1_42.h"
#include "base_func.h"

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

#define MAX_FIND_RANGE 0x1000
namespace {
	const int KSYM_NAME_LEN = 128;
}
KallsymsLookupName_6_1_42::KallsymsLookupName_6_1_42(const std::vector<char>& file_buf) : m_file_buf(file_buf)
{
}

KallsymsLookupName_6_1_42::~KallsymsLookupName_6_1_42()
{
}

bool KallsymsLookupName_6_1_42::init() {
	size_t offset_list_start = 0, offset_list_end = 0;
	if (!find_kallsyms_offsets_list(offset_list_start, offset_list_end)) {
		std::cout << "Unable to find the list of kallsyms offsets" << std::endl;
		return false;
	}
	size_t kallsyms_relative_base_offset = 0;
	m_kallsyms_relative_base = find_kallsyms_relative_base(offset_list_end, kallsyms_relative_base_offset);
	if (!m_kallsyms_relative_base) {
		std::cout << "Unable to find the kallsyms relative base" << std::endl;
		return false;
	}

	std::cout << std::hex << "kallsyms_relative_base: 0x" << m_kallsyms_relative_base << std::endl;

	size_t kallsyms_relative_base_end_offset = kallsyms_relative_base_offset + sizeof(uint64_t);
	size_t kallsyms_num_offset = 0;
	m_kallsyms_num = find_kallsyms_num(offset_list_start, offset_list_end, kallsyms_relative_base_end_offset, kallsyms_num_offset);
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
	bool markers_list_is_align8 = false;
	if (!find_kallsyms_markers_list(m_kallsyms_num, name_list_end, markers_list_start, markers_list_end, markers_list_is_align8)) {
		std::cout << "Unable to find the list of kallsyms markers list" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_markers_start: 0x" << markers_list_start << std::endl;
	std::cout << std::hex << "kallsyms_markers_end: 0x" << markers_list_end << std::endl;
	m_kallsyms_markers.offset = markers_list_start;

	size_t seqs_of_names_list_start = 0;
	size_t seqs_of_names_list_end = 0;
	if (!find_kallsyms_seqs_of_names_list(m_kallsyms_num, markers_list_end, markers_list_is_align8, seqs_of_names_list_start, seqs_of_names_list_end)) {
		std::cout << "Unable to find the list of kallsyms seqs names list" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_seqs_of_names_list_start: 0x" << seqs_of_names_list_start << std::endl;
	std::cout << std::hex << "kallsyms_seqs_of_names_list_end: 0x" << seqs_of_names_list_end << std::endl;
	m_kallsyms_seqs_of_names.offset = seqs_of_names_list_start;
	
	size_t token_table_start = 0;
	size_t token_table_end = 0;
	if (!find_kallsyms_token_table(seqs_of_names_list_end, token_table_start, token_table_end)) {
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

bool KallsymsLookupName_6_1_42::is_inited() {
	return m_inited;
}

int KallsymsLookupName_6_1_42::get_kallsyms_num() {
	return m_kallsyms_num;
}
bool KallsymsLookupName_6_1_42::find_kallsyms_offsets_list(size_t& start, size_t& end) {
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

uint64_t KallsymsLookupName_6_1_42::find_kallsyms_relative_base(size_t offset_list_end, size_t& kallsyms_relative_base_offset) {
	//unsigned int val1 = *(unsigned int*)&m_file_buf[offset_list_end];
	unsigned int val2 = *(unsigned int*)&m_file_buf[offset_list_end + sizeof(unsigned int)];
	if (val2 == 0xFFFFFFC0) {
		kallsyms_relative_base_offset = offset_list_end;
		return *(uint64_t*)&m_file_buf[offset_list_end];
	}
	return 0;
}

int KallsymsLookupName_6_1_42::find_kallsyms_num(size_t offset_list_start, size_t offset_list_end, size_t kallsyms_relative_base_end_offset, size_t& kallsyms_num_offset) {
	size_t size = (offset_list_end - offset_list_start) / sizeof(int);
	size_t allow_min_size = size - 10;
	size_t allow_max_size = size + 10;
	auto _min = MIN(m_file_buf.size(), MAX_FIND_RANGE);
	int cnt = 10;
	for (size_t x = 0; (x + sizeof(int)) < _min; x++) {
		auto pos = kallsyms_relative_base_end_offset + x * sizeof(int);
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


bool KallsymsLookupName_6_1_42::find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end) {
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


bool KallsymsLookupName_6_1_42::find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end, bool & markers_list_is_align8) {
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

	markers_list_is_align8 = false;
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
			markers_list_is_align8 = true;
			break;
		}
	}
	if (markers_list_is_align8) {
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

bool KallsymsLookupName_6_1_42::find_kallsyms_seqs_of_names_list(int kallsyms_num, size_t markers_list_end_offset, bool markers_list_is_align8, size_t& seqs_of_names_list_start, size_t& seqs_of_names_list_end) {
	size_t start = align8(markers_list_end_offset);
	seqs_of_names_list_start = start;
	if (markers_list_is_align8) {
		seqs_of_names_list_end = seqs_of_names_list_start + kallsyms_num * sizeof(long) * 2;
	} else {
		seqs_of_names_list_end = seqs_of_names_list_start + kallsyms_num * sizeof(long);
	}
	return true;
}

bool KallsymsLookupName_6_1_42::find_kallsyms_token_table(size_t seqs_of_names_list_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end) {
	size_t start = align8(seqs_of_names_list_end_offset);
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

bool KallsymsLookupName_6_1_42::find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start) {
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

bool KallsymsLookupName_6_1_42::find_kallsyms_sym_func_entry_offset(size_t& kallsyms_sym_func_entry_offset) {
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
unsigned int KallsymsLookupName_6_1_42::kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen)
{
	int len, skipped_first = 0;
	const char* tptr;
	const uint8_t* data;
	const uint8_t* kallsyms_names = (uint8_t*)&m_file_buf[m_kallsyms_names.offset];
	const uint16_t* kallsyms_token_index = (uint16_t*)&m_file_buf[m_kallsyms_token_index.offset];
	const unsigned char* kallsyms_token_table = (unsigned char*)&m_file_buf[m_kallsyms_token_table.offset];

	/* Get the compressed symbol length from the first symbol byte. */
	data = &kallsyms_names[off];
	len = *data;
	data++;
	off++;

	/* If MSB is 1, it is a "big" symbol, so needs an additional byte. */
	if ((len & 0x80) != 0) {
		len = (len & 0x7F) | (*data << 7);
		data++;
		off++;
	}

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */
	while (len) {
		tptr = (const char*)& kallsyms_token_table[kallsyms_token_index[*data]];
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

/*
 * Find the offset on the compressed stream given and index in the
 * kallsyms array.
 */
unsigned int KallsymsLookupName_6_1_42::get_symbol_offset(unsigned long pos) {
	const uint8_t* name;
	int i, len;

	/*
	 * Use the closest marker we have. We have markers every 256 positions,
	 * so that should be close enough.
	 */
	uint8_t* kallsyms_names = (uint8_t*)&m_file_buf[m_kallsyms_names.offset];
	unsigned int markers_index = *(unsigned int*)&m_file_buf[m_kallsyms_markers.offset + (pos >> 8) * sizeof(unsigned int)];
	name = &kallsyms_names[markers_index];

	/*
	 * Sequentially scan all the symbols up to the point we're searching
	 * for. Every symbol is stored in a [<len>][<len> bytes of data] format,
	 * so we just need to add the len to the current pointer for every
	 * symbol we wish to skip.
	 */
	for (i = 0; i < (pos & 0xFF); i++) {
		len = *name;

		/*
		 * If MSB is 1, it is a "big" symbol, so we need to look into
		 * the next byte (and skip it, too).
		 */
		if ((len & 0x80) != 0)
			len = ((len & 0x7F) | (name[1] << 7)) + 1;

		name = name + len + 1;
	}

	return name - kallsyms_names;
}

bool KallsymsLookupName_6_1_42::cleanup_symbol_name(char* s) {
	char* res;

	//TODO:
	//if (!IS_ENABLED(CONFIG_LTO_CLANG))
	//	return false;

	/*
	 * LLVM appends various suffixes for local functions and variables that
	 * must be promoted to global scope as part of LTO.  This can break
	 * hooking of static functions with kprobes. '.' is not a valid
	 * character in an identifier in C. Suffixes only in LLVM LTO observed:
	 * - foo.llvm.[0-9a-f]+
	 */
	res = strstr(s, ".llvm.");
	if (res) {
		*res = '\0';
		return true;
	}

	return false;
}

int KallsymsLookupName_6_1_42::compare_symbol_name(const char* name, char* namebuf) {
	int ret;

	ret = strcmp(name, namebuf);
	if (!ret)
		return ret;

	if (cleanup_symbol_name(namebuf) && !strcmp(name, namebuf))
		return 0;

	return ret;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int KallsymsLookupName_6_1_42::kallsyms_lookup_names(const char* name, unsigned int* start, unsigned int* end) {
	int ret;
	int low, mid, high;
	unsigned int seq, off;
	char namebuf[KSYM_NAME_LEN];
	unsigned int* kallsyms_seqs_of_names = (unsigned int*)& m_file_buf[m_kallsyms_seqs_of_names.offset];

	low = 0;
	high = m_kallsyms_num - 1;

	while (low <= high) {
		mid = low + (high - low) / 2;
		seq = kallsyms_seqs_of_names[mid];
		off = get_symbol_offset(seq);
		kallsyms_expand_symbol(off, namebuf, ARRAY_SIZE(namebuf));
		ret = compare_symbol_name(name, namebuf);
		if (ret > 0)
			low = mid + 1;
		else if (ret < 0)
			high = mid - 1;
		else
			break;
	}

	if (low > high)
		return -ESRCH;

	low = mid;
	while (low) {
		seq = kallsyms_seqs_of_names[low - 1];
		off = get_symbol_offset(seq);
		kallsyms_expand_symbol(off, namebuf, ARRAY_SIZE(namebuf));
		if (compare_symbol_name(name, namebuf))
			break;
		low--;
	}
	*start = low;

	if (end) {
		high = mid;
		while (high < m_kallsyms_num - 1) {
			seq = kallsyms_seqs_of_names[high + 1];
			off = get_symbol_offset(seq);
			kallsyms_expand_symbol(off, namebuf, ARRAY_SIZE(namebuf));
			if (compare_symbol_name(name, namebuf))
				break;
			high++;
		}
		*end = high;
	}

	return 0;
}

uint64_t KallsymsLookupName_6_1_42::kallsyms_sym_address(int idx)
{
	int* kallsyms_offsets = (int*)&m_file_buf[m_kallsyms_offsets.offset];

	//TODO:
	//if (!IS_ENABLED(CONFIG_KALLSYMS_BASE_RELATIVE))
	//	return kallsyms_addresses[idx];

	/* values are unsigned offsets if --absolute-percpu is not in effect */
	//TODO:
	//if (!IS_ENABLED(CONFIG_KALLSYMS_ABSOLUTE_PERCPU))
	//	return kallsyms_relative_base + (u32)kallsyms_offsets[idx];

	/* ...otherwise, positive offsets are absolute values */
	if (kallsyms_offsets[idx] >= 0)
		return kallsyms_offsets[idx];

	/* ...and negative offsets are relative to kallsyms_relative_base - 1 */
	return m_kallsyms_relative_base - 1 - kallsyms_offsets[idx];
}

/* Lookup the address for this symbol. Returns 0 if not found. */
uint64_t KallsymsLookupName_6_1_42::__kallsyms_lookup_name(const char* name, bool include_str_mode) {
	int ret;
	unsigned int i;
	unsigned int* kallsyms_seqs_of_names = (unsigned int*)&m_file_buf[m_kallsyms_seqs_of_names.offset];

	/* Skip the search for empty string. */
	if (!*name)
		return 0;

	ret = kallsyms_lookup_names(name, &i, NULL);
	if (!ret)
		return kallsyms_sym_address(kallsyms_seqs_of_names[i]);

	return 0;
}

uint64_t KallsymsLookupName_6_1_42::kallsyms_lookup_name(const char* name, bool include_str_mode) {
	if (!m_inited) { return 0;  }
	return __kallsyms_lookup_name(name, include_str_mode);
}
