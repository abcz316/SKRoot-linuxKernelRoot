#pragma once
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <sys/system_properties.h>

namespace device_detect {

static inline std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static inline bool equals_ignore_case(std::string_view a, std::string_view b) {
    return lower_copy(std::string(a)) == lower_copy(std::string(b));
}

static inline bool contains_ignore_case(std::string_view a, std::string_view b) {
    auto aa = lower_copy(std::string(a));
    auto bb = lower_copy(std::string(b));
    return aa.find(bb) != std::string::npos;
}

static inline std::string get_prop(const char* key) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(key, value);
    if (len <= 0) return {};
    return std::string(value, static_cast<size_t>(len));
}

static inline bool equals_any_ignore_case(
    std::string_view value,
    const char* const* candidates,
    size_t candidate_count
) {
    for (size_t i = 0; i < candidate_count; ++i) {
        if (equals_ignore_case(value, candidates[i])) {
            return true;
        }
    }
    return false;
}

static inline bool contains_any_ignore_case(
    std::string_view value,
    const char* const* candidates,
    size_t candidate_count
) {
    for (size_t i = 0; i < candidate_count; ++i) {
        if (contains_ignore_case(value, candidates[i])) {
            return true;
        }
    }
    return false;
}

static inline bool is_device_by_brand_tokens(
    const char* const* brand_tokens,
    size_t brand_token_count
) {
    const char* strong_keys[] = {
        "ro.product.brand",
        "ro.product.manufacturer",
        "ro.product.vendor.brand",
        "ro.product.vendor.manufacturer",
        "ro.product.odm.brand",
        "ro.product.odm.manufacturer",
        "ro.product.system.brand",
        "ro.product.system.manufacturer",
        "ro.product.system_ext.brand",
        "ro.product.system_ext.manufacturer",
    };

    for (const char* key : strong_keys) {
        std::string v = get_prop(key);
        if (equals_any_ignore_case(v, brand_tokens, brand_token_count)) {
            return true;
        }
    }

    // 弱兜底：某些 ROM brand / manufacturer 不完整，但 model / name / fingerprint 里仍带品牌名。
    const char* weak_keys[] = {
        "ro.product.model",
        "ro.product.vendor.model",
        "ro.product.name",
        "ro.product.device",
        "ro.build.product",
        "ro.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.product.build.fingerprint",
    };

    for (const char* key : weak_keys) {
        std::string v = get_prop(key);
        if (contains_any_ignore_case(v, brand_tokens, brand_token_count)) {
            return true;
        }
    }

    return false;
}

static inline bool is_oneplus_device() {
    const char* brands[] = {
        "oneplus",
    };
    return is_device_by_brand_tokens(brands, sizeof(brands) / sizeof(brands[0]));
}

static inline bool is_oppo_device() {
    const char* brands[] = {
        "oppo",
    };
    return is_device_by_brand_tokens(brands, sizeof(brands) / sizeof(brands[0]));
}

// 推荐业务层用这个：识别 OnePlus / OPPO 设备。
static inline bool is_oplus_device() {
    const char* brands[] = {
        "oneplus",
        "oppo",
    };
    return is_device_by_brand_tokens(brands, sizeof(brands) / sizeof(brands[0]));
}

} // namespace device_detect