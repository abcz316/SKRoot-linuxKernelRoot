#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <cstring>

namespace boot_session_utils {
namespace detail {
    static void trim_ascii_space_inplace(std::string& s) {
        // 去掉前后空白：' ', '\t', '\r', '\n'
        auto is_space = [](unsigned char c) {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        };
        size_t b = 0;
        while (b < s.size() && is_space((unsigned char)s[b])) ++b;
        size_t e = s.size();
        while (e > b && is_space((unsigned char)s[e - 1])) --e;
        if (b == 0 && e == s.size()) return;
        s = s.substr(b, e - b);
    }

}
static std::string read_boot_session() {
    // Linux: /proc/sys/kernel/random/boot_id
    // 内容通常是一行 UUID + '\n'
    FILE* fp = std::fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!fp) return {};

    char buf[128] = {0};
    // 读第一行即可
    if (!std::fgets(buf, sizeof(buf), fp)) {
        std::fclose(fp);
        return {};
    }
    std::fclose(fp);

    std::string id(buf);
    detail::trim_ascii_space_inplace(id);
    return id;
}

}
