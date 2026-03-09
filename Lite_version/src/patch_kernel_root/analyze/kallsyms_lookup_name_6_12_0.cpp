#include "kallsyms_lookup_name_6_12_0.h"
#include "find_static_code_start.h"

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

#define A64_NOP 0xD503201F
#define R_AARCH64_RELATIVE 1027
#define MAX_FIND_RANGE 0x1000
namespace {
	const int KSYM_NAME_LEN = 128;
	struct Elf64_Rela {
		uint64_t r_offset = 0;
		uint64_t r_info = 0;
		uint64_t r_addend = 0;
	};

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
KallsymsLookupName_6_12_0::KallsymsLookupName_6_12_0(const std::vector<char>& file_buf) : m_file_buf(file_buf)
{
}

KallsymsLookupName_6_12_0::~KallsymsLookupName_6_12_0()
{
}

bool KallsymsLookupName_6_12_0::init() {
	size_t code_static_start = find_static_code_start(m_file_buf);
	std::cout << std::hex << "code_static_start: 0x" << code_static_start << std::endl;

	size_t offset_list_start = 0, offset_list_end = 0;

	size_t kallsyms_relative_base_offset = 0;
	std::vector<size_t> maybe_kallsyms_num_offset;

	if (find_kallsyms_offsets_list(offset_list_start, offset_list_end)) {
		std::cout << std::hex << "fisrt kallsyms_offset_start: 0x" << offset_list_start << std::endl;
		std::cout << std::hex << "fisrt kallsyms_offset_end: 0x" << offset_list_end << std::endl;

		kallsyms_relative_base_offset = find_kallsyms_relative_base_offset(offset_list_end);
		if (!kallsyms_relative_base_offset) {
			std::cout << "Unable to find the kallsyms relative base" << std::endl;
			return false;
		}
		m_kallsyms_relative_base = rd64_le(m_file_buf, kallsyms_relative_base_offset);

		std::cout << std::hex << "kallsyms_relative_base: 0x" << m_kallsyms_relative_base << ", offset: 0x" << kallsyms_relative_base_offset << std::endl;

		maybe_kallsyms_num_offset = find_maybe_kallsyms_num(offset_list_start, offset_list_end);
		if (!maybe_kallsyms_num_offset.size()) {
			std::cout << "Unable to find the num of kallsyms offset list" << std::endl;
			return false;
		}

	} else {
		std::cout << "Unable to find the list of 'kallsyms offsets' and 'kallsyms addresses'" << std::endl;
		return false;
	}

	for (size_t offset : maybe_kallsyms_num_offset) {
		m_kallsyms_num = *(uint32_t*)&m_file_buf[offset];
		std::cout << std::hex << "current kallsyms_num: 0x" << m_kallsyms_num << ", offset: 0x" << offset << std::endl;

		// revise the offset list offset again
		const int offset_list_var_len = sizeof(uint32_t);
		offset_list_start = offset_list_end - m_kallsyms_num * offset_list_var_len;
		uint32_t test_first_offset_list_val;
		do {
			test_first_offset_list_val = *(uint32_t*)&m_file_buf[offset_list_start];
			if (test_first_offset_list_val) {
				offset_list_start -= offset_list_var_len;
				offset_list_end -= offset_list_var_len;
			}
		} while (test_first_offset_list_val);
		std::cout << std::hex << "kallsyms_offset_start: 0x" << offset_list_start << std::endl;
		std::cout << std::hex << "kallsyms_offset_end: 0x" << offset_list_end << std::endl;
		m_kallsyms_offsets.offset = offset_list_start;

		size_t kallsyms_num_end_offset = offset + sizeof(m_kallsyms_num);
		size_t name_list_start = 0, name_list_end = 0;
		if (!find_kallsyms_names_list(m_kallsyms_num, kallsyms_num_end_offset, name_list_start, name_list_end)) {
			std::cout << "Unable to find the list of kallsyms names list" << std::endl;
			continue;
		}
		std::cout << std::hex << "kallsyms_names_start: 0x" << name_list_start << std::endl;
		std::cout << std::hex << "kallsyms_names_end: 0x" << name_list_end << std::endl;
		m_kallsyms_names.offset = name_list_start;

		size_t markers_list_start = 0;
		size_t markers_list_end = 0;
		bool markers_list_is_align8 = false;
		if (!find_kallsyms_markers_list(m_kallsyms_num, name_list_end, markers_list_start, markers_list_end, markers_list_is_align8)) {
			std::cout << "Unable to find the list of kallsyms markers list" << std::endl;
			continue;
		}
		std::cout << std::hex << "kallsyms_markers_start: 0x" << markers_list_start << std::endl;
		std::cout << std::hex << "kallsyms_markers_end: 0x" << markers_list_end << std::endl;
		m_kallsyms_markers.offset = markers_list_start;

		size_t token_table_start = 0;
		size_t token_table_end = 0;
		if (!find_kallsyms_token_table(markers_list_end, token_table_start, token_table_end)) {
			std::cout << "Unable to find the list of kallsyms token table" << std::endl;
			continue;
		}
		std::cout << std::hex << "kallsyms_token_table_start: 0x" << token_table_start << std::endl;
		std::cout << std::hex << "kallsyms_token_table_end: 0x" << token_table_end << std::endl;
		m_kallsyms_token_table.offset = token_table_start;

		size_t token_index_start = 0;
		if (!find_kallsyms_token_index(token_table_end, token_index_start)) {
			std::cout << "Unable to find the list of kallsyms token index" << std::endl;
			continue;
		}
		std::cout << std::hex << "kallsyms_token_index_start: 0x" << token_index_start << std::endl;
		m_kallsyms_token_index.offset = token_index_start;

		size_t seqs_of_names_list_start = 0;
		size_t seqs_of_names_list_end = 0;
		if (!find_kallsyms_seqs_of_names_list(m_kallsyms_num, kallsyms_relative_base_offset + sizeof(uint64_t), markers_list_is_align8, seqs_of_names_list_start, seqs_of_names_list_end)) {
			std::cout << "Unable to find the list of kallsyms seqs names list" << std::endl;
			continue;
		}
		std::cout << std::hex << "kallsyms_seqs_of_names_list_start: 0x" << seqs_of_names_list_start << std::endl;
		std::cout << std::hex << "kallsyms_seqs_of_names_list_end: 0x" << seqs_of_names_list_end << std::endl;
		m_kallsyms_seqs_of_names.offset = seqs_of_names_list_start;

		if (!resolve_kallsyms_offset_symbol_base(code_static_start, m_kallsyms_offsets.base_off)) {
			std::cout << "Unable to find the list of kallsyms sym function entry offset" << std::endl;
			return false;
		}

		m_kallsyms_symbols_cache.clear();
		m_inited = true;
		break;
	}
	return true;
}

bool KallsymsLookupName_6_12_0::is_inited() {
	return m_inited;
}

int KallsymsLookupName_6_12_0::get_kallsyms_num() {
	return m_kallsyms_num;
}

static bool __find_kallsyms_offsets_list(const std::vector<char>& file_buf, size_t max_cnt, size_t& start, size_t& end) {
	const int var_len = sizeof(uint32_t);
	for (auto x = 0; x + var_len < file_buf.size(); x += var_len) {
		uint32_t val1 = *(uint32_t*)&file_buf[x];
		uint32_t val2 = *(uint32_t*)&file_buf[x + var_len];
		if (val1 != 0 || val1 >= val2) {
			continue;
		}
		int cnt = 0;
		auto j = x + var_len;
		for (; j + var_len < file_buf.size(); j += var_len) {
			val1 = *(uint32_t*)&file_buf[j];
			val2 = *(uint32_t*)&file_buf[j + var_len];
			if (val1 > val2 || val2 == 0 || (val2 - val1) > 0x1000000) {
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

bool KallsymsLookupName_6_12_0::find_kallsyms_offsets_list(size_t& start, size_t& end) {
	for (auto i = 60000; i > 30000; i -= 5000) {
		if (__find_kallsyms_offsets_list(m_file_buf, i, start, end)) {
			return true;
		}
	}
	return false;
}

size_t KallsymsLookupName_6_12_0::find_kallsyms_relative_base_offset(size_t offset_list_end) {
	for (int i = 0; i < 5; i++) {
		auto off = offset_list_end + sizeof(unsigned int) * i;
		uint64_t val = rd64_le(m_file_buf, off);
		if (looks_kernel_va(val)) {
			return off;
		}
	}
	return 0;
}

std::vector<size_t> KallsymsLookupName_6_12_0::find_maybe_kallsyms_num(size_t offset_list_start, size_t offset_list_end) {
	//Search upwards
	if (offset_list_start < MAX_FIND_RANGE) {
		std::cout << "The starting position of kallsyms offset list is too small and abnormal." << std::endl;
		return {};
	}
	std::vector<size_t> maybe_kallsyms_num;
	for (int i = 0; i < 10; i++) {
		uint32_t val1 = *(uint32_t*)&m_file_buf[offset_list_start - i * sizeof(uint32_t)];
		if (val1 != 0) {
			break;
		}
		maybe_kallsyms_num.push_back((offset_list_end - offset_list_start + i * sizeof(uint32_t)) / sizeof(uint32_t));
	}
	if (maybe_kallsyms_num.size() == 0) {
		std::cout << "Unable to find the kallsyms num, not even a single possibility." << std::endl;
		return {};
	}

	// Go further and find 'kallsyms num'
	std::vector<size_t> maybe_kallsyms_num_offset;
	for (size_t maybe_num : maybe_kallsyms_num) {
		const int kallsyms_token_index_len = 256 * sizeof(short);
		for (size_t b = MAX_FIND_RANGE; b < offset_list_start - kallsyms_token_index_len; b += sizeof(uint32_t)) {
			uint32_t num = *(uint32_t*)&m_file_buf[b];
			if (num == maybe_num) {
				maybe_kallsyms_num_offset.push_back(b);
			}
		}
	}
	if (maybe_kallsyms_num_offset.size() == 0) {
		std::cout << "Unable to find the kallsyms num offset, not even a single possibility." << std::endl;
		return {};
	}
	std::reverse(maybe_kallsyms_num_offset.begin(), maybe_kallsyms_num_offset.end());
	return maybe_kallsyms_num_offset;
}

bool KallsymsLookupName_6_12_0::find_kallsyms_names_list(int kallsyms_num, size_t kallsyms_num_end_offset, size_t& name_list_start, size_t& name_list_end) {
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
		if (ch == 0) {
			break;
		}
		off += ch;
	}
	name_list_end = off;
	return true;
}


bool KallsymsLookupName_6_12_0::find_kallsyms_markers_list(int kallsyms_num, size_t name_list_end_offset, size_t& markers_list_start, size_t& markers_list_end, bool & markers_list_is_align8) {
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
	
	auto exist_val_start = markers_list_start + var_len;

	markers_list_is_align8 = false;
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
			markers_list_is_align8 = true;
			break;
		}
	}
	if (markers_list_is_align8) {
		size_t back_val = align_up<8>(markers_list_start) - markers_list_start;
		if (back_val == 0) {
			markers_list_start -= 8;
		} else {
			markers_list_start -= back_val; // 4
		}
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(uint32_t) * 2;
	} else {
		markers_list_end = markers_list_start + ((kallsyms_num + 255) >> 8) * sizeof(uint32_t);
	}
	
	return true;
}

bool KallsymsLookupName_6_12_0::find_kallsyms_seqs_of_names_list(int kallsyms_num, size_t kallsyms_relative_base_end_offset, bool markers_list_is_align8, size_t& seqs_of_names_list_start, size_t& seqs_of_names_list_end) {
	/*
	output_label("kallsyms_seqs_of_names");
	for (i = 0; i < table_cnt; i++)
		printf("\t.byte 0x%02x, 0x%02x, 0x%02x\n",
			(unsigned char)(table[i]->seq >> 16),
			(unsigned char)(table[i]->seq >> 8),
			(unsigned char)(table[i]->seq >> 0));
	printf("\n");
	
	*/
	//We need to observe if there are continuous and regular '0x00' after it

	size_t start = align_up<8>(kallsyms_relative_base_end_offset);
	seqs_of_names_list_start = start;
	//TODO: Perhaps 8-byte alignment is not required here?
	//if (markers_list_is_align8) {
	//	seqs_of_names_list_end = seqs_of_names_list_start + kallsyms_num * 3 + 1;
	//} else {
		seqs_of_names_list_end = seqs_of_names_list_start + kallsyms_num * 3;
	//}
	return true;
}

bool KallsymsLookupName_6_12_0::find_kallsyms_token_table(size_t kallsyms_markers_end_offset, size_t& kallsyms_token_table_start, size_t& kallsyms_token_table_end) {
	size_t start = align_up<8>(kallsyms_markers_end_offset);
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

bool KallsymsLookupName_6_12_0::find_kallsyms_token_index(size_t kallsyms_token_table_end, size_t& kallsyms_token_index_start) {
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

bool KallsymsLookupName_6_12_0::resolve_kallsyms_offset_symbol_base(size_t code_static_start, int& base_off) {
	if (!has_kallsyms_symbol("_stext")) {
		return false;
	}
	if (has_kallsyms_symbol("_text")) {
		base_off = kallsyms_lookup_name("_text");
		if (base_off) return true;
	}
	size_t _stext_offset = kallsyms_lookup_name("_stext");
	base_off = code_static_start - _stext_offset;
	return true;
}

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * if uncompressed string is too long (>= maxlen), it will be truncated,
 * given the offset to where the symbol is in the compressed stream.
 */
unsigned int KallsymsLookupName_6_12_0::kallsyms_expand_symbol(unsigned int off, char* result, size_t maxlen)
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

uint64_t KallsymsLookupName_6_12_0::kallsyms_sym_address(int idx) {
	/* values are unsigned offsets if --absolute-percpu is not in effect */
	//TODO:
	//if (!IS_ENABLED(CONFIG_KALLSYMS_ABSOLUTE_PERCPU))
	//	return kallsyms_relative_base + (u32)kallsyms_offsets[idx];

	/* ...otherwise, positive offsets are absolute values */
	int* kallsyms_offsets = (int*)&m_file_buf[m_kallsyms_offsets.offset];

	if (kallsyms_offsets[idx] >= 0)
		return kallsyms_offsets[idx];

	/* ...and negative offsets are relative to kallsyms_relative_base - 1 */
	return m_kallsyms_relative_base - 1 - kallsyms_offsets[idx];
}

/* Lookup the address for this symbol. Returns 0 if not found. */
uint64_t KallsymsLookupName_6_12_0::kallsyms_lookup_name(const char* name) {
	std::unordered_map<std::string, uint64_t> syms = kallsyms_on_each_symbol();
	auto iter = syms.find(name);
	if (iter == syms.end()) {
		return 0;
	}
	return iter->second;
}

std::unordered_map<std::string, uint64_t> KallsymsLookupName_6_12_0::kallsyms_on_each_symbol() {
	if (!m_kallsyms_symbols_cache.size()) {
		for (auto i = 0, off = 0; i < m_kallsyms_num; i++) {
			char namebuf[KSYM_NAME_LEN] = { 0 };
			off = kallsyms_expand_symbol(off, namebuf, sizeof(namebuf));

			uint64_t offset = kallsyms_sym_address(i);
			offset += m_kallsyms_offsets.base_off;
			m_kallsyms_symbols_cache[namebuf] = offset;
		}
	}
	return m_kallsyms_symbols_cache;
}

bool KallsymsLookupName_6_12_0::has_kallsyms_symbol(const char* name) {
	std::unordered_map<std::string, uint64_t> syms = kallsyms_on_each_symbol();
	auto iter = syms.find(name);
	return iter != syms.end();
}