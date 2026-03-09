#pragma once
#include <string>
#include <string_view>
#include <ostream>
#include <type_traits>
#include <sys/types.h>

#define KROOTERR_LIST_INIT(X) \
X(OK,        = 0)        \
X(ERR_PARAM,       = -10000)

#define KROOTERR_LIST_AUTO(X) \
X(ERR_NO_ROOT,) \
X(ERR_READ_CHILD_ERRCODE,) \
X(ERR_READ_CHILD_STRING,) \
X(ERR_READ_CHILD_INT,) \
X(ERR_READ_CHILD_UINT64,) \
X(ERR_READ_CHILD_SET_ARR,) \
X(ERR_READ_CHILD_MAP_I_S,) \
X(ERR_READ_CHILD_MAP_S_I,) \
X(ERR_READ_EOF,) \
X(ERR_NO_MEM,) \
X(ERR_EXECVE,) \
X(ERR_KILL,) \
X(ERR_APP_DIR,) \
X(ERR_FIND_CMDLINE_PROC,) \
X(ERR_EXIST_32BIT,) \
X(ERR_NOT_EXIST_ORIGINAL_FILE,) \
X(ERR_NOT_EXIST_IMPLANT_FILE,) \
X(ERR_CHMOD,) \
X(ERR_COPY_SELINUX,) \
X(ERR_LINK_SO,) \
X(ERR_CHECK_LINK_SO,) \
X(ERR_NOT_FOUND_LIBC,) \
X(ERR_LOAD_LIBC_FUNC_ADDR,) \
X(ERR_INJECT_PROC64_ENV,) \
X(ERR_INJECT_PROC64_SO,) \
X(ERR_INJECT_PROC64_RUN_EXIT,) \
X(ERR_LIBC_PATH_EMPTY,) \
X(ERR_CREATE_SU_HIDE_FOLDER,) \
X(ERR_DEL_SU_HIDE_FOLDER,) \
X(ERR_WRITE_ROOT_SERVER,) \
X(ERR_WRITE_SU_ENV_SO_FILE,) \
X(ERR_WRITE_SU_EXEC,) \
X(ERR_SET_FILE_SELINUX,) \
X(ERR_DEL_HIDE_FOLDER,) \
X(ERR_POPEN,) \
X(ERR_OPEN_FILE,) \
X(ERR_OPEN_DIR,) \
X(ERR_NOT_ELF64_FILE,) \
X(ERR_DLOPEN_FILE,) \
X(ERR_PID_NOT_FOUND,)

enum class KRootErr : ssize_t {
#define DECL_ENUM(name, assign) name assign,
    KROOTERR_LIST_INIT(DECL_ENUM)
#undef DECL_ENUM
#define DECL_ENUM(name, assign) name,
    KROOTERR_LIST_AUTO(DECL_ENUM)
#undef DECL_ENUM
};

constexpr bool is_ok(KRootErr err) noexcept {
    return err == KRootErr::OK;
}

constexpr bool is_failed(KRootErr err) noexcept {
    return err != KRootErr::OK;
}

#define RETURN_ON_ERROR(expr)                                             \
    do {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr), KRootErr>::value,                \
            "RETURN_ON_ERROR: expr 必须返回 KRootErr"                       \
        );                                                                \
        KRootErr _err = (expr);                                            \
        if (is_failed(_err))                                      \
            return _err;                                                  \
    } while (0)

#define BREAK_ON_ERROR(expr)                                              \
    do {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr), KRootErr>::value,                \
            "BREAK_ON_ERROR: expr 必须返回 KRootErr"                        \
        );                                                                \
        KRootErr _err = (expr);                                            \
        if (is_failed(_err))                                      \
            break;                                                        \
    } while (0)


constexpr ssize_t to_num(KRootErr err) noexcept {
    return static_cast<ssize_t>(err);
}

constexpr std::string_view krooterr_name_sv(KRootErr e) {
    switch (e) {
#define DECL_CASE(name, assign) case KRootErr::name: return std::string_view(#name);
        KROOTERR_LIST_INIT(DECL_CASE)
        KROOTERR_LIST_AUTO(DECL_CASE)
#undef DECL_CASE
    }
    return {};
}

inline std::string to_string(KRootErr e) {
    if (auto sv = krooterr_name_sv(e); !sv.empty()) return std::string(sv);
    return "Unknown(" + std::to_string(static_cast<ssize_t>(e)) + ")";
}

inline std::ostream& operator<<(std::ostream& os, KRootErr e) {
    if (auto sv = krooterr_name_sv(e); !sv.empty()) return os << sv;
    return os << "Unknown(" << static_cast<ssize_t>(e) << ")";
}