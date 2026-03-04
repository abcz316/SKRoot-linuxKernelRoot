#pragma once
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <cstdio>
#include <cstdarg>
#include <cstring>   // strerror
#include <thread>
#include <chrono>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "kernel_module_kit_umbrella.h"

namespace fs = std::filesystem;
static inline constexpr const char* kKeyPersistDataPermBackup = "persist_data_perm_backup_v1";
static inline const fs::path kPersistDataDir = "/mnt/vendor/persist/data";

/* ===================== 统一封装日志（100% 走这里） ===================== */
static inline void km_logv_(const char* level, const char* tag, const char* fmt, va_list ap) {
    std::printf("[persist_perm][%s][%s] ", level, tag);
    std::vprintf(fmt, ap);
    std::printf("\n");
}

static inline void km_logi(const char* tag, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    km_logv_("I", tag, fmt, ap);
    va_end(ap);
}

static inline void km_loge(const char* tag, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    km_logv_("E", tag, fmt, ap);
    va_end(ap);
}

static inline void km_log_errno(const char* tag, const fs::path& p) {
    const int e = errno;
    km_loge(tag, "path=%s errno=%d(%s)", p.c_str(), e, std::strerror(e));
}

static inline void km_log_ec(const char* tag, const fs::path& p, const std::error_code& ec) {
    km_loge(tag, "path=%s ec=%d(%s)", p.c_str(), ec.value(), ec.message().c_str());
}

/* ===================== 业务实现 ===================== */

static inline bool chmod_nofollow(const fs::path& p, mode_t mode) {
    struct stat st{};
    if (::lstat(p.c_str(), &st) != 0) {
        if (errno == ENOENT) return true;
        km_log_errno("lstat_failed", p);
        return false;
    }
    if (S_ISLNK(st.st_mode)) return true;

    if (::fchmodat(AT_FDCWD, p.c_str(), mode, 0) != 0) {
        km_log_errno("fchmodat_failed", p);
        return false;
    }
    return true;
}

// 序列化：每行 "<perm_octal> <path>"
static inline bool make_perm_backup_text(const fs::path& target_dir, std::string& out_text) {
    std::error_code ec;
    if (!fs::exists(target_dir, ec)) {
        if (ec) {
            km_log_ec("exists_failed", target_dir, ec);
            return false;
        }
        out_text.clear();
        return true;
    }

    std::ostringstream ss;

    auto dump_one = [&](const fs::path& p) -> bool {
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) {
            if (errno == ENOENT) return true;
            km_log_errno("dump_lstat_failed", p);
            return false;
        }
        unsigned perm = static_cast<unsigned>(st.st_mode & 07777);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04o", perm);
        ss << buf << " " << p.string() << "\n";
        return true;
    };

    if (!dump_one(target_dir)) {
        km_loge("dump_root_failed", "root=%s", target_dir.c_str());
        return false;
    }

    fs::recursive_directory_iterator it(target_dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        km_log_ec("rdir_iter_init_failed", target_dir, ec);
        return false;
    }

    for (const auto& entry : it) {
        if (!dump_one(entry.path())) {
            km_loge("dump_entry_failed", "path=%s", entry.path().c_str());
            return false;
        }
    }

    out_text = ss.str();
    return true;
}

static inline bool restore_perm_from_text(const std::string& text) {
    if (text.empty()) return true; // 没备份就不恢复

    std::istringstream ss(text);
    std::string line;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;

        std::istringstream ls(line);
        std::string perm_oct;
        if (!(ls >> perm_oct)) {
            km_loge("parse_failed", "bad perm token, line='%s'", line.c_str());
            return false;
        }

        std::string path;
        std::getline(ls, path);
        if (!path.empty() && path[0] == ' ') path.erase(0, 1);
        if (path.empty()) {
            km_loge("parse_failed", "empty path, line='%s'", line.c_str());
            return false;
        }

        unsigned perm = 0;
        {
            std::istringstream ps(perm_oct);
            ps >> std::oct >> perm;
            if (!ps) {
                km_loge("parse_failed", "bad oct perm='%s', line='%s'",
                        perm_oct.c_str(), line.c_str());
                return false;
            }
        }

        const fs::path fp(path);
        if (!chmod_nofollow(fp, static_cast<mode_t>(perm & 07777))) {
            km_loge("restore_chmod_failed", "path=%s perm=%04o", fp.c_str(), (perm & 07777));
            return false;
        }
    }
    return true;
}

// ====== 初始化：备份 -> 写入disk_storage ======
static inline bool persist_data_on_install_backup_permissions() {
    std::string backup_text;
    if (!make_perm_backup_text(kPersistDataDir, backup_text)) {
        km_loge("init_backup_perm_failed", "make_perm_backup_text failed, dir=%s", kPersistDataDir.c_str());
        return false;
    }

    if (is_failed(kernel_module::write_string_disk_storage(kKeyPersistDataPermBackup, backup_text.c_str()))) {
        km_loge("init_backup_perm_failed", "write_string_disk_storage failed, key=%s", kKeyPersistDataPermBackup);
        return false;
    }

    km_logi("init_backup_perm_ok", "backup done, dir=%s", kPersistDataDir.c_str());
    return true;
}

// ====== 安装：chmod 000 ======
static inline bool persist_data_on_install_lockdown_permissions() {
    // chmod 000：根 + 递归
    if (!chmod_nofollow(kPersistDataDir, 0000)) {
        km_loge("install_failed", "chmod root failed, dir=%s", kPersistDataDir.c_str());
        return false;
    }

    std::error_code ec;
    fs::recursive_directory_iterator it(kPersistDataDir, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        km_log_ec("install_rdir_iter_init_failed", kPersistDataDir, ec);
        return false;
    }

    for (const auto& entry : it) {
        if (!chmod_nofollow(entry.path(), 0000)) {
            km_loge("install_failed", "chmod entry failed, path=%s", entry.path().c_str());
            return false;
        }
    }

    km_logi("install_ok", "lockdown done, dir=%s", kPersistDataDir.c_str());
    return true;
}

// ====== 卸载：读disk_storage -> 恢复 ======
static inline bool persist_data_on_uninstall_restore_permissions() {
    std::string backup_text;
    if (is_failed(kernel_module::read_string_disk_storage(kKeyPersistDataPermBackup, backup_text))) {
        km_loge("uninstall_failed", "read_string_disk_storage failed, key=%s", kKeyPersistDataPermBackup);
        return false;
    }

    if (!restore_perm_from_text(backup_text)) {
        km_loge("uninstall_failed", "restore_perm_from_text failed");
        return false;
    }

    km_logi("uninstall_ok", "restore done");
    return true;
}
