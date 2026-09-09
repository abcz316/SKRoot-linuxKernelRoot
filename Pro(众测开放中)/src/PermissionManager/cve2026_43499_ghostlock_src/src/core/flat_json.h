#pragma once

/*
 * FlatJson — 纯 C 实现的扁平 JSON 读写封装（基于 cJSON）。
 *
 * 仅依赖 C99，保持 main.c 可用 C 编译器编译。
 * 整数统一以十六进制字符串保存，避免 cJSON double 对 uint64_t 的精度损失。
 */

#include "cJSON/cJSON.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

typedef struct FlatJson {
    cJSON *root;
} FlatJson;

/* 初始化：创建一个空对象。 */
static inline void flat_json_init(FlatJson *j) {
    j->root = cJSON_CreateObject();
}

/* 释放内部对象。 */
static inline void flat_json_destroy(FlatJson *j) {
    if (j && j->root) {
        cJSON_Delete(j->root);
        j->root = NULL;
    }
}

/* 解析 JSON。成功后替换当前内容；失败时保留原内容不变。 */
static inline bool flat_json_parse(FlatJson *j, const char *text, size_t len) {
    cJSON *parsed = cJSON_ParseWithLength(text, len);
    if (!parsed) return false;
    if (!cJSON_IsObject(parsed)) {
        cJSON_Delete(parsed);
        return false;
    }
    cJSON_Delete(j->root);
    j->root = parsed;
    return true;
}

static inline const cJSON *flat_json_find(const FlatJson *j, const char *key) {
    if (!j->root || !key) return NULL;
    return cJSON_GetObjectItemCaseSensitive(j->root, key);
}

/* 解析无符号整数字符串（支持 0x 十六进制前缀），整个串必须被消费。 */
static inline bool flat_json_parse_u64_string(const char *text, size_t len, uint64_t *out) {
    if (len == 0) return false;

    int base = 10;
    size_t i = 0;
    if (len >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        i = 2;
        base = 16;
    }
    if (i >= len) return false;

    uint64_t value = 0;
    for (; i < len; i++) {
        char c = text[i];
        int digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (base == 16) {
            if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
        } else {
            return false;
        }
        if (digit >= base) return 0;
        if (value > (UINT64_MAX - (uint64_t)digit) / (uint64_t)base) return false;
        value = value * (uint64_t)base + (uint64_t)digit;
    }
    *out = value;
    return true;
}

/* 从 cJSON 节点解析无符号 64 位整数（字符串或 number）。 */
static inline bool flat_json_parse_unsigned(const cJSON *item, uint64_t *out) {
    if (!item) return false;

    if (cJSON_IsString(item) && item->valuestring) {
        size_t slen = strlen(item->valuestring);
        return flat_json_parse_u64_string(item->valuestring, slen, out);
    }

    if (cJSON_IsNumber(item)) {
        /* 兼容普通 JSON number，仅接受 double 可精确表示的整数范围。 */
        const double kMaxExactInteger = 9007199254740991.0; /* 2^53 - 1 */
        const double value = item->valuedouble;

        if (!isfinite(value) || value < 0.0 || value > kMaxExactInteger ||
            floor(value) != value)
            return false;

        *out = (uint64_t)value;
        return true;
    }

    return false;
}

static inline bool flat_json_get_u32(const FlatJson *j, const char *key, uint32_t *out) {
    uint64_t value = 0;
    if (!flat_json_parse_unsigned(flat_json_find(j, key), &value)) return false;
    if (value > 0xFFFFFFFFu) return false;
    *out = (uint32_t)value;
    return true;
}

static inline bool flat_json_get_u64(const FlatJson *j, const char *key, uint64_t *out) {
    return flat_json_parse_unsigned(flat_json_find(j, key), out);
}

static inline uint32_t flat_json_get_u32_or(const FlatJson *j, const char *key, uint32_t default_value) {
    uint32_t value = 0;
    return flat_json_get_u32(j, key, &value) ? value : default_value;
}

static inline uint64_t flat_json_get_u64_or(const FlatJson *j, const char *key, uint64_t default_value) {
    uint64_t value = 0;
    return flat_json_get_u64(j, key, &value) ? value : default_value;
}
