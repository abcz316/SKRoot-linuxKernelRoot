#include "kallsyms_lookup_name.h"
#include "find_static_code_start.h"

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

#define A64_NOP 0xD503201F
#define MAX_FIND_RANGE 0x1000
namespace {
	const int KSYM_NAME_LEN = 128;

	static inline bool looks_kernel_va(uint64_t v) {
		static const uint64_t starts[] = {
			0xFFFFFFC000000000ULL, // VA_BITS=39
			0xFFFFFE0000000000ULL, // VA_BITS=42
			0xFFFF800000000000ULL, // VA_BITS=48
			0xFFF8000000000000ULL  // VA_BITS=52
		};
		for (unsigned i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i) {
			if ((v & starts[i]) == starts[i]) return true;
		}
		return false;
	}
}
KallsymsLookupName::KallsymsLookupName(const std::vector<char>& file_buf) : m_file_buf(file_buf)
{
}

KallsymsLookupName::~KallsymsLookupName()
{
}

bool KallsymsLookupName::init() {
	size_t code_static_start = find_static_code_start(m_file_buf);
	std::cout << std::hex << "code_static_start: 0x" << code_static_start << std::endl;

	size_t addresses_list_start = 0, addresses_list_end = 0;
	if (!find_kallsyms_addresses_list(addresses_list_start, addresses_list_end)) {
		std::cout << "Unable to find the list of 'kallsyms addresses'" << std::endl;
		return false;
	}
	size_t kallsyms_num_offset = 0;
	m_kallsyms_num = find_kallsyms_num(addresses_list_start, addresses_list_end, 10, kallsyms_num_offset);
	if (!m_kallsyms_num) {
		std::cout << "Unable to find the num of kallsyms addresses list" << std::endl;
		return false;
	}
	std::cout << std::hex << "kallsyms_num: 0x" << m_kallsyms_num << ", offset: 0x" << kallsyms_num_offset << std::endl;

	addresses_list_start = addresses_list_end - m_kallsyms_num * sizeof(uint64_t);
	std::cout << std::hex << "kallsyms_addresses_start: 0x" << addresses_list_start << std::endl;
	std::cout << std::hex << "kallsyms_addresses_end: 0x" << addresses_list_end << std::endl;
	m_kallsyms_addresses.offset = addresses_list_start;

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

	if (!resolve_kallsyms_addresses_symbol_base(code_static_start, m_kallsyms_addresses.base_address)) {
		std::cout << "Unable to find the list of kallsyms addresses symbol base" << std::endl;
		return false;
	}
	m_kallsyms_symbols_cache.clear();
	m_inited = true;
	return true;
}

bool KallsymsLookupName::is_inited() {
	return m_inited;
}

int KallsymsLookupName::get_kallsyms_num() {
	return m_kallsyms_num;
}

static bool __find_kallsyms_addresses_list(const std::vector<char>& file_buf, size_t max_cnt, size_t& start, size_t& end) {
	const int var_len = sizeof(uint64_t);
	for (auto x = 0; x + var_len < file_buf.size(); x += var_len) {
		uint64_t val1 = rd64_le(file_buf, x);
		uint64_t val2 = rd64_le(file_buf, x + var_len);
		if (val1 != 0 || val1 >= val2 || !looks_kernel_va(val2)) {
			continue;
		}
		int cnt = 0;
		auto j = x + var_len;
		for (; j + var_len < file_buf.size(); j += var_len) {
			val1 = rd64_le(file_buf, j);
			val2 = rd64_le(file_buf, j + var_len);
			if (val1 > val2 || val2 == 0 || val2 == 0x1000000000000000) {
				j += var_len;
				break;
			}
			cnt++;
		}
		if (cnt >= max_cnt) {
			start = x;
			end = j;
			return true;
		}
	}
	return false;
}
bool KallsymsLookupName::find_kallsyms_addresses_list(size_t& start, size_t& end) {
	for (auto i = 60000; i > 30000; i -= 5000) {
		if (__find_kallsyms_addresses_list(m_file_buf, i, start, end)) {
			return true;
		}
	}
	return false;
}

int KallsymsLookupName::find_kallsyms_num(size_t addresses_list_start, size_t addresses_list_end, size_t fuzzy_range, size_t& kallsyms_num_offset) {
	size_t size = (addresses_list_end - addresses_list_start) / sizeof(uint64_t);
	size_t allow_min_size = size - fuzzy_range;
	size_t allow_max_size = size + fuzzy_range;
	auto _min = MIN(m_file_buf.size(), MAX_FIND_RANGE);
	int cnt = 10;
	for (size_t x = 0; (x + sizeof(int)) < _min; x++) {
		auto pos = addresses_list_end + x * sizeof(int);
		int val = *(int*)&m_file_buf[pos];
		if (val == 0) {
			continue;
		}
		if (val >= allow_min_size && val <= allow_max_size) {
			kallsyms_num_offset = pos;
			return val;
		}
		if (--cnt == 0) {
			break;
		}
	}
	return 0;
}


bool KallsymsLookupName::find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end) {

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


bool KallsymsLookupName::find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end) {
	size_t start = align_up<8>(name_list_end_offset);
	const int var_len = sizeof(uint32_t);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		uint32_t val1 = *(uint32_t*)&m_file_buf[x];
		uint32_t val2 = *(uint32_t*)&m_file_buf[x + var_len];
		if (val1 == 0 && val2 > 0) {
			markers_list_start = x;
			break;
		} else if (val1 == 0 && val2 == 0) {
			continue;
		}
		return false;
	}

	bool is_align8 = false;
	int cnt = 5;
	uint32_t last_second_var_val = 0;
	for (auto y = markers_list_start + var_len; y + var_len < m_file_buf.size(); y += var_len * 2) {
		uint32_t val1 = *(uint32_t*)&m_file_buf[y];
		uint32_t val2 = *(uint32_t*)&m_file_buf[y + var_len];
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
		size_t back_val = align_up<8>(markers_list_start) - markers_list_start;
		if (back_val == 0) {
			markers_list_start -= 8;
		}
		else {
			markers_list_start -= back_val; // 4
		}
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(uint32_t) * 2;
	}
	else {
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(uint32_t);
	}

	return true;
}

bool KallsymsLookupName::find_kallsyms_token_table(size_t markers_list_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end) {
	size_t start = align_up<8>(markers_list_end_offset);
	const int var_len = sizeof(uint32_t);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		uint32_t val1 = *(uint32_t*)&m_file_buf[x];
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

bool KallsymsLookupName::find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start) {
	size_t start = align_up<8>(kallsyms_token_table_end);
	const int var_len = sizeof(short);
	for (auto x = start; x + var_len < m_file_buf.size(); x += var_len) {
		short val1 = *(short*)&m_file_buf[x];
		short val2 = *(short*)&m_file_buf[x + var_len];
		if (val1 == 0 && val2 > 0) {
			kallsyms_token_index_start = x;
			break;
		} else if (val1 == 0 && val2 == 0) {
			continue;
		}
		return false;
	}
	return true;
}

bool KallsymsLookupName::resolve_kallsyms_addresses_symbol_base(size_t code_static_start, uint64_t& base_address) {
	if (!has_kallsyms_symbol("_stext")) {
		return false;
	}
	if (has_kallsyms_symbol("_text")) {
		base_address = kallsyms_lookup_name("_text");
		return true;
	}
	uint64_t _stext_addr = kallsyms_lookup_name("_stext");
	base_address = _stext_addr - code_static_start;
	return true;
}

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * if uncompressed string is too long (>= maxlen), it will be truncated,
 * given the offset to where the symbol is in the compressed stream.
 */
unsigned int KallsymsLookupName::kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen)
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
uint64_t KallsymsLookupName::kallsyms_lookup_name(const char* name) {
	std::unordered_map<std::string, uint64_t> syms = kallsyms_on_each_symbol();
	auto iter = syms.find(name);
	if (iter == syms.end()) {
		return 0;
	}
	return iter->second;
}

std::unordered_map<std::string, uint64_t> KallsymsLookupName::kallsyms_on_each_symbol() {
	if (!m_kallsyms_symbols_cache.size()) {
		for (auto i = 0, off = 0; i < m_kallsyms_num; i++) {
			char namebuf[KSYM_NAME_LEN] = { 0 };
			off = kallsyms_expand_symbol(off, namebuf, sizeof(namebuf));

			uint64_t offset = rd64_le(m_file_buf, m_kallsyms_addresses.offset + i * sizeof(uint64_t));
			offset -= m_kallsyms_addresses.base_address;
			m_kallsyms_symbols_cache[namebuf] = offset;
		}
	}
	return m_kallsyms_symbols_cache;
}

bool KallsymsLookupName::has_kallsyms_symbol(const char* name) {
	std::unordered_map<std::string, uint64_t> syms = kallsyms_on_each_symbol();
	auto iter = syms.find(name);
	return iter != syms.end();
}