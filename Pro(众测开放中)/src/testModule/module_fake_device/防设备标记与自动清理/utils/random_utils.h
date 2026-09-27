#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <numeric>
#include <random>
#include <string>
#include <vector>

namespace random_utils {

namespace detail {

// 线程局部的 32 位 RNG
inline std::mt19937& mt19937_32() {
    thread_local std::mt19937 gen{ std::random_device{}() };
    return gen;
}

// 线程局部的 64 位 RNG（用于随机字符串）
inline std::mt19937_64& mt19937_64() {
    using clock = std::chrono::steady_clock;
    thread_local std::mt19937_64 gen{
        static_cast<std::mt19937_64::result_type>(
            clock::now().time_since_epoch().count()
        )
    };
    return gen;
}

} // namespace detail

// 生成 count 个 [1,255] 之间互不相同的字节
// count == 0 或 > 255 时返回空 vector
inline std::vector<std::uint8_t> generate_unique_non_zero_bytes(std::size_t count) {
    if (count == 0 || count > 255) {
        return {};
    }

    std::vector<std::uint8_t> pool(255);
    std::iota(pool.begin(), pool.end(), static_cast<std::uint8_t>(1));

    std::shuffle(pool.begin(), pool.end(), detail::mt19937_32());

    return std::vector<std::uint8_t>(pool.begin(), pool.begin() + count);
}

// 利用 int32_t 均匀分布 + 位型重解释，得到均匀的 uint32_t
inline std::uint32_t random_u32_from_i32() {
    using dist_t = std::uniform_int_distribution<std::int32_t>;
    static thread_local dist_t dist(
        std::numeric_limits<std::int32_t>::min(),
        std::numeric_limits<std::int32_t>::max()
    );

    std::int32_t value = dist(detail::mt19937_32());
    return static_cast<std::uint32_t>(value);
}

// 生成闭区间 [min_inclusive, max_inclusive] 内的随机 uint32_t（含端点）
inline std::uint32_t random_u32_from_i32(std::uint32_t min_inclusive, std::uint32_t max_inclusive) {
    if (min_inclusive > max_inclusive) {
        std::uint32_t t = min_inclusive;
        min_inclusive = max_inclusive;
        max_inclusive = t;
    }
    if (min_inclusive == max_inclusive) return min_inclusive;
    const std::uint64_t span = static_cast<std::uint64_t>(max_inclusive) - static_cast<std::uint64_t>(min_inclusive) + 1ULL;
    // 覆盖整个 uint32_t 范围（0..UINT32_MAX）
    if (span == (1ULL << 32)) {
        return random_u32_from_i32();
    }
    const std::uint64_t limit = ((1ULL << 32) / span) * span;
    std::uint32_t v;
    do {
        v = random_u32_from_i32();
    } while (static_cast<std::uint64_t>(v) >= limit);
    return min_inclusive + static_cast<std::uint32_t>(static_cast<std::uint64_t>(v) % span);
}

// 生成由 [a-zA-Z0-9] 组成的随机字符串
inline std::string generate_random_str(std::size_t len) {
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    static constexpr std::size_t alphabet_size = sizeof(alphabet) - 1;

    if (len == 0) {
        return {};
    }

    using dist_t = std::uniform_int_distribution<std::size_t>;
    static thread_local dist_t dist(0, alphabet_size - 1);

    std::string key;
    key.reserve(len);

    auto& rng = detail::mt19937_64();
    for (std::size_t i = 0; i < len; ++i) {
        key += alphabet[dist(rng)];
    }

    return key;
}

// 生成由 [a-zA-Z0-9.] 组成的随机字符串
inline std::string generate_random_str_with_dot(std::size_t len) {
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        ".";
    static constexpr std::size_t alphabet_size = sizeof(alphabet) - 1;

    if (len == 0) {
        return {};
    }

    using dist_t = std::uniform_int_distribution<std::size_t>;
    static thread_local dist_t dist(0, alphabet_size - 1);

    std::string key;
    key.reserve(len);

    auto& rng = detail::mt19937_64();
    for (std::size_t i = 0; i < len; ++i) {
        key += alphabet[dist(rng)];
    }

    return key;
}


// 生成由 [a-zA-Z.] 组成的随机字符串（不含数字）
inline std::string generate_random_str_with_dot_no_digits(std::size_t len) {
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ".";
    static constexpr std::size_t alphabet_size = sizeof(alphabet) - 1;

    if (len == 0) {
        return {};
    }

    using dist_t = std::uniform_int_distribution<std::size_t>;
    static thread_local dist_t dist(0, alphabet_size - 1);

    std::string key;
    key.reserve(len);

    auto& rng = detail::mt19937_64();
    for (std::size_t i = 0; i < len; ++i) {
        key += alphabet[dist(rng)];
    }

    return key;
}

} // namespace random_utils
