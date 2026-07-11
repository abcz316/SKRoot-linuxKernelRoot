#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include "exec_cmdline_utils.h"
#include "android_system_property_utils.h"

enum class ResetPropMode {
    kTrigger,     // 普通 resetprop，可能触发 property change
    kNoTrigger    // resetprop -n，静默修改
};
enum class PropertyCheckMode {
    kSetWhenDangerValue, // 当前值等于 danger_value 才修改
    kSetWhenNotSafeValue // 当前值不是 safe_value 就修改
};

namespace resetprop {
namespace detail {

static inline std::string& resetprop_bin_path_ref() {
    static std::string path;
    return path;
}

static inline std::string shell_quote(const char* s) {
    if (!s) return "''";
    std::string out;
    out.reserve(std::strlen(s) + 8);

    out.push_back('\'');
    for (const char* p = s; *p; ++p) {
        if (*p == '\'') {
            out += "'\\''";
        } else {
            out.push_back(*p);
        }
    }
    out.push_back('\'');
    return out;
}

static inline bool should_set_property(const std::string& old_value,
                                       const char* danger_value,
                                       const char* safe_value,
                                       PropertyCheckMode check_mode) {
    switch (check_mode) {
        case PropertyCheckMode::kSetWhenDangerValue:
            return danger_value && old_value == danger_value;

        case PropertyCheckMode::kSetWhenNotSafeValue:
            return safe_value && old_value != safe_value;

        default:
            return false;
    }
}

} // namespace detail

static inline bool init(const std::string& resetprop_bin_path) {
    if (resetprop_bin_path.empty()) {
        return false;
    }

    detail::resetprop_bin_path_ref() = resetprop_bin_path;
    return true;
}

static inline const std::string& get_resetprop_bin_path() {
    return detail::resetprop_bin_path_ref();
}

static inline bool has_resetprop_bin_path() {
    return !detail::resetprop_bin_path_ref().empty();
}

static inline bool set_property_value(const char* key,
                                      const char* value,
                                      ResetPropMode resetprop_mode = ResetPropMode::kNoTrigger) {
    if (!key || !*key) return false;
    if (!value) return false;
    if (detail::resetprop_bin_path_ref().empty()) return false;

    std::string cmdline = detail::shell_quote(detail::resetprop_bin_path_ref().c_str());

    if (resetprop_mode == ResetPropMode::kNoTrigger) {
        cmdline += " -n";
    }

    cmdline += " ";
    cmdline += detail::shell_quote(key);
    cmdline += " ";
    cmdline += detail::shell_quote(value);
    printf("%s\n", cmdline.c_str());
    fork_execve_cmdline(cmdline.c_str());
    return true;
}

static inline bool check_and_set_property(const char* key,
                                          const char* danger_value,
                                          const char* safe_value,
                                          PropertyCheckMode check_mode,
                                          ResetPropMode resetprop_mode = ResetPropMode::kNoTrigger) {
    if (!key || !*key) return false;
    if (!safe_value) return false;

    const std::string old_value = get_system_property(key);

    if (!detail::should_set_property(old_value, danger_value, safe_value, check_mode)) {
        return false;
    }

    return set_property_value(key, safe_value, resetprop_mode);
}

} // namespace resetprop