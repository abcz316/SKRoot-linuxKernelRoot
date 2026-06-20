#pragma once
#include <string>
#include <unistd.h>
#include <sys/system_properties.h>

static std::string get_system_property(const char* key) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(key, value);
    if (len <= 0) return {};
    return std::string(value, static_cast<size_t>(len));
}
