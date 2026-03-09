#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/xattr.h>

namespace file_utils {
    
static bool file_exists(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

static bool read_file_bytes(const char* path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    if (n < 0) return false;

    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(n));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), n));
}

static inline bool create_empty_file(const char* target_path) {
    std::ofstream file(target_path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!file.is_open()) return false;
    file.close();
    return true;
}

static bool make_dirs(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::create_directories(p, ec);
}

static bool create_directory_if_not_exists(const char* dir_path) {
    if (!file_exists(dir_path)) {
        make_dirs(dir_path);
    }
    return file_exists(dir_path);
}

static bool delete_path(const std::filesystem::path& dir_path) {
    std::error_code ec;
    std::filesystem::remove_all(dir_path, ec);
    return !file_exists(dir_path);
}

#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

#ifndef SELINUX_SYSTEM_FILE_FLAG
#define SELINUX_SYSTEM_FILE_FLAG "u:object_r:system_file:s0"
#endif

#ifndef SELINUX_KERNEL_FILE_FLAG
#define SELINUX_KERNEL_FILE_FLAG "u:object_r:kernel:s0"
#endif

enum class SelinuxFileFlag {
  SELINUX_SYSTEM_FILE,
  SELINUX_KERNEL_FILE,
};

static inline bool set_file_selinux_access_mode(const char* file_full_path, SelinuxFileFlag flag) {
    if (chmod(file_full_path, 0777) != 0) {
        return false;
    }
    const char* selinux_flag = flag == SelinuxFileFlag::SELINUX_SYSTEM_FILE ? SELINUX_SYSTEM_FILE_FLAG : SELINUX_KERNEL_FILE_FLAG;
    if (setxattr(file_full_path,
                 XATTR_NAME_SELINUX,
                 selinux_flag,
                 strlen(selinux_flag) + 1,
                 0) != 0) {
        return false;
    }
    return true;
}

} // namespace file_utils
