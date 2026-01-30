#pragma once
#include <random>
#include <cstdint>
#define STATIC_ASSERT_SIZE_MULTIPLE_OF_4(x) \
    static_assert(sizeof(x) % 4 == 0, #x " sizeof() must be multiple of 4")
    
namespace kernel_module {
/***************************************************************************
 * 向上对齐 N 字节（N 必须是 4 的倍数）
 * 参数: v — 待对齐的值
 * 返回: 向上对齐后的值
 * For example:
 *   align_up<4>(5)   // 返回 8
 *   align_up<8>(17)  // 返回 24
 ***************************************************************************/
static inline size_t align_up(size_t v, size_t align) {
    if ((align & (align - 1)) != 0) return v;
    return (v + (align - 1)) & ~(align - 1);
}

template <size_t N>
static inline constexpr size_t align_up(size_t v) {
    static_assert((N & (N - 1)) == 0, "N must be power of two");
    return align_up(v, N);
}

/***************************************************************************
 * 判断对齐
 ***************************************************************************/
template <size_t N>
static inline constexpr bool is_aligned(uint64_t v) {
    static_assert((N & (N - 1)) == 0, "N must be power of two");
    return (v & (static_cast<uint64_t>(N) - 1)) == 0;
}
}
