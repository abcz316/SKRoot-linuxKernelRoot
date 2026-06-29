#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <sys/system_properties.h>

namespace device_detect {

static inline std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c));});
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

static std::string get_prop(const char* key) {
        char value[PROP_VALUE_MAX] = {0};
        int len = __system_property_get(key, value);
        if (len <= 0) return {};
        return std::string(value, static_cast<size_t>(len));
}

static inline bool is_oneplus_device() {
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
        if (equals_ignore_case(v, "oneplus")) {
            return true;
        }
    }

    // 弱兜底：某些 ROM 可能 brand 不完整，但型号 / 指纹里仍带 OnePlus
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
        if (contains_ignore_case(v, "oneplus")) {
            return true;
        }
    }
    return false;
}

} // namespace device_detect