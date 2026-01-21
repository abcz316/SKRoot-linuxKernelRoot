#pragma once
#include <string>
#include <string_view>
#include <ostream>
#include <type_traits>
#include <sys/types.h>

#define KMODERR_LIST_INIT(X) \
X(OK,= 0)        \
X(ERR_MODULE_PARAM,= -20000)

#define KMODERR_LIST_AUTO(X) \
X(ERR_MODULE_TEST_CHANNEL,) \
X(ERR_MODULE_NO_BOOT,) \
X(ERR_MODULE_BOOT_SESSION,) \
X(ERR_MODULE_ASM,) \
X(ERR_MODULE_FUNC_NOT_STANDARD,) \
X(ERR_MODULE_ADDR_NOT_ALGIN4,) \
X(ERR_MODULE_START_ADDR,) \
X(ERR_MODULE_GET_CPU,) \
X(ERR_MODULE_SET_CPU,) \
X(ERR_MODULE_AVC_DENIED_PATCH,) \
X(ERR_MODULE_AUDIT_PATCH,) \
X(ERR_MODULE_SYMBOL_PARAM,) \
X(ERR_MODULE_SYMBOL_NOT_EXIST,) \
X(ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER,) \
X(ERR_MODULE_PR_GET_NAME,) \
X(ERR_MODULE_PR_SET_NAME,) \
X(ERR_MODULE_GET_AUXV_SIGNATURE,) \
X(ERR_MODULE_HOOK_FUNC_NOT_STANDARD,) \
X(ERR_MODULE_HOOK_INSN_NOT_SUPPORT,) \
X(ERR_MODULE_IDLE_MEM_NOT_FOUND,) \
X(ERR_MODULE_IDLE_MEM_NOT_ENOUGH,) \
X(ERR_MODULE_IDLE_MEM_UNKNOW,) \
X(ERR_MODULE_STORAGE_NOT_FOUND,) \
X(ERR_MODULE_STORAGE_WRITE,) \
X(ERR_MODULE_STORAGE_READ,) \
X(ERR_MODULE_STORAGE_TYPE,) \
X(ERR_MODULE_OFFSET_CACHE_NOT_FOUND,) \
X(ERR_MODULE_OFFSET_CACHE_WRITE,) \
X(ERR_MODULE_OFFSET_CACHE_READ,) \
X(ERR_MODULE_OFFSET_CACHE_TYPE,) \
X(ERR_MODULE_OFFSET_NOT_MATCH_LINUX_VER,) \
X(ERR_MODULE_OFFSET_NOT_FOUND,) \
X(ERR_MODULE_DENTRY_EMPTY,) \
X(ERR_MODULE_GET_CAPS,) \
X(ERR_MODULE_NO_ROOT,) \
X(ERR_MODULE_CRED_DANGER,) \
X(ERR_MODULE_DLOPEN,) \
X(ERR_MODULE_DLBLOB,) \
X(ERR_MODULE_DLSYM,) \
X(ERR_MODULE_PARSE_ZIP_FILE,) \
X(ERR_MODULE_ELF_FILE_NOT_FOUND,) \
X(ERR_MODULE_PARSE_NAME,) \
X(ERR_MODULE_PARSE_UUID32,) \
X(ERR_MODULE_PARSE_VERSION,) \
X(ERR_MODULE_PARSE_DESC,) \
X(ERR_MODULE_PARSE_AUTHOR,) \
X(ERR_MODULE_PARSE_MIN_SDK,) \
X(ERR_MODULE_REJECT_INSTALL,) \
X(ERR_MODULE_REQUIRE_MIN_SDK,) \
X(ERR_MODULE_SDK_TOO_OLD,) \
X(ERR_MODULE_FILE_NOT_EXIST,) \
X(ERR_MODULE_CREATE_EMPTY_FILE,) \
X(ERR_MODULE_OPEN_FILE,) \
X(ERR_MODULE_WRITE_FILE,) \
X(ERR_MODULE_READ_FILE,) \
X(ERR_MODULE_DEL_FILE,) \
X(ERR_MODULE_OPEN_DIR,) \
X(ERR_MODULE_DEL_DIR,) \
X(ERR_MODULE_CREATE_DIR,) \
X(ERR_MODULE_SU_LIST_NOT_FOUND,) \
X(ERR_MODULE_UID_PP_ADDR_NOT_FOUND,) \
X(ERR_MODULE_WEB_UI_LOADER_NOT_EXIST,) \
X(ERR_MODULE_WEB_UI_SERVER_NOT_EXIST,) \
X(ERR_MODULE_WEB_UI_SERVER_RUNNING,) \
X(ERR_MODULE_WEB_UI_SERVER_NOT_RUNNING,) \
X(ERR_SKROOT_ENV_NOT_INSTALL,) \
X(ERR_SET_FILE_SELINUX,) \
X(ERR_READ_CHILD_ERRCODE,) \
X(ERR_READ_CHILD_STRING,) \
X(ERR_READ_CHILD_INT,) \
X(ERR_READ_CHILD_DATA,) \
X(ERR_READ_EOF,) \
X(ERR_WRITE_SU_EXEC,) \
X(ERR_WRITE_WEBUI_LOADER_EXEC,) \
X(ERR_WRITE_AUTORUN_BOOSTRAP,) \
X(ERR_NO_MEM,)

enum class KModErr : ssize_t {
#define DECL_ENUM(name,assign) name assign,
    KMODERR_LIST_INIT(DECL_ENUM)
#undef DECL_ENUM
#define DECL_ENUM(name,assign) name,
    KMODERR_LIST_AUTO(DECL_ENUM)
#undef DECL_ENUM
};

constexpr bool is_ok(KModErr err) noexcept {
    return err == KModErr::OK;
}

constexpr bool is_failed(KModErr err) noexcept {
    return err != KModErr::OK;
}

#define RETURN_IF_ERROR(expr)                                             \
    do {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr),KModErr>::value,                  \
            "RETURN_IF_ERROR: expr 必须返回 KModErr"                       \
        );                                                                \
        KModErr _err = (expr);                                            \
        if (is_failed(_err))                                      \
            return _err;                                                  \
    } while (0)

#define BREAK_IF_ERROR(expr)                                              \
    {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr),KModErr>::value,                   \
            "BREAK_IF_ERROR: expr 必须返回 KModErr"                        \
        );                                                                \
        KModErr _err = (expr);                                            \
        if (is_failed(_err))                                      \
            break;                                                        \
    }

constexpr ssize_t to_num(KModErr err) noexcept {
    return static_cast<ssize_t>(err);
}

constexpr std::string_view kmoderr_name_sv(KModErr e) {
    switch (e) {
#define DECL_CASE(name,assign) case KModErr::name: return std::string_view(#name);
        KMODERR_LIST_INIT(DECL_CASE)
        KMODERR_LIST_AUTO(DECL_CASE)
#undef DECL_CASE
    }
    return {};
}

inline std::string to_string(KModErr e) {
    if (auto sv = kmoderr_name_sv(e); !sv.empty()) return std::string(sv);
    return "Unknown(" + std::to_string(static_cast<ssize_t>(e)) + ")";
}
