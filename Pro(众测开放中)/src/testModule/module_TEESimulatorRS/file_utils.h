#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>

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

static bool write_file_bytes(const char* path, const void* data, size_t size) {
    if (!path) return false;
    std::ofstream f(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!f) return false;
    if (data && size > 0) {
        f.write(static_cast<const char*>(data),
                static_cast<std::streamsize>(size));
    }
    return f.good();
}

static bool read_text_file(const char* target_path, std::string& text) {
    std::vector<uint8_t> buf;
	if(!read_file_bytes(target_path, buf)) return false;
	text.assign(buf.begin(), buf.end());
    return true;
}

static bool write_text_file(const char* target_path, std::string_view text) {
    if (!target_path) return false;
    std::ofstream file(target_path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) return false;
    file << text;
    return file.good();
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

static bool copy_dir(const std::filesystem::path& src, const std::filesystem::path& dst) {
    std::error_code ec;
    std::filesystem::create_directories(dst, ec);
    if (ec) return false;
    std::filesystem::copy(src, dst,
             std::filesystem::copy_options::recursive |
             std::filesystem::copy_options::overwrite_existing,
             ec);
    return !ec;
}

} // namespace file_utils
