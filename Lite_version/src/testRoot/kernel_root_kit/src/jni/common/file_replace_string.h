#include <algorithm>
#include <cstring>
#include <memory>
#include <string_view>

static bool replace_feature_string_in_buf(const char *feature_string_buf, size_t feature_string_buf_size, std::string_view new_string, char *buf, size_t buf_size) {
	bool write = false;
	std::shared_ptr<char> sp_new_feature(new (std::nothrow) char[feature_string_buf_size], std::default_delete<char[]>());
	if(sp_new_feature) {
		memset(sp_new_feature.get(), 0, feature_string_buf_size);
		size_t copy_len = new_string.length() + 1;
		copy_len = std::min(feature_string_buf_size - 1, copy_len);
		strncpy(sp_new_feature.get(), new_string.data(), copy_len);

		for (size_t i = 0; i <= buf_size - feature_string_buf_size; i++) {
			char * desc = buf;
			desc += i;
			if (memcmp(desc, feature_string_buf, feature_string_buf_size) == 0) {
				memcpy(desc, sp_new_feature.get(), copy_len);
				write = true;
				desc += feature_string_buf_size;
			}
		}
	}
	return write;
}
