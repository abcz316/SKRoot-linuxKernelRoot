#pragma once

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <set>
#include <string>
#include <system_error>
#include <vector>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "json_helper.h"

#ifndef MY_TASK_COMM_LEN
#define MY_TASK_COMM_LEN 16
#endif

namespace fs = std::filesystem;

namespace list_dir_helper {

struct FileItem {
    std::string name;
    std::string type = "other";
    bool is_dir = false;
    std::string date;
    std::string time;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
    uint32_t mode = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    bool hide_protected = false;
};


inline void format_local_time(std::time_t t, std::string& out_date, std::string& out_time) {
    char date_buf[16] = {0};
    char time_buf[16] = {0};

    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif

    std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tmv);
    std::strftime(time_buf, sizeof(time_buf), "%H:%M", &tmv);

    out_date = date_buf;
    out_time = time_buf;
}

inline std::string read_self_comm() {
    char comm[MY_TASK_COMM_LEN] = {};
    if (::prctl(PR_GET_NAME, comm, 0, 0, 0) != 0) return {};
    return std::string(comm);
}

inline bool set_self_comm(const std::string& name) {
    if (name.empty()) return false;
    constexpr size_t kMaxVisibleLen = MY_TASK_COMM_LEN - 1;
    std::string truncated = name.substr(0, kMaxVisibleLen);
    char scrub[MY_TASK_COMM_LEN] = {};
    for (size_t i = 0; i < kMaxVisibleLen; ++i) {
        scrub[i] = 'X';
    }
    scrub[kMaxVisibleLen] = '\0';
    for (size_t null_pos = kMaxVisibleLen; ; --null_pos) {
        scrub[null_pos] = '\0';
        ::prctl(PR_SET_NAME, scrub, 0, 0, 0);
        if (null_pos == 0) break;
    }
    return ::prctl(PR_SET_NAME, truncated.c_str(), 0, 0, 0) == 0;
}

class ScopedProcComm {
public:
    ScopedProcComm() : m_old_comm(read_self_comm()) {}

    bool set_temp(const std::string& new_comm) {
        if (new_comm.empty()) return false;
        return set_self_comm(new_comm);
    }

    ~ScopedProcComm() {
        if (!m_old_comm.empty()) {
            set_self_comm(m_old_comm);
        }
    }

private:
    std::string m_old_comm;
};


inline bool fill_file_item_from_entry(const fs::directory_entry& entry, FileItem& item) {
    item.name = entry.path().filename().string();

    struct stat st {};
    if (::lstat(entry.path().c_str(), &st) == 0) {
        item.is_dir = S_ISDIR(st.st_mode);
        if (S_ISDIR(st.st_mode)) item.type = "directory";
        else if (S_ISREG(st.st_mode)) item.type = "file";
        else if (S_ISLNK(st.st_mode)) {
            item.type = "symlink";
            // Browsing a symlink to a directory should behave like a directory.
            // Keep the reported type as symlink so copy/move operations still
            // preserve the link itself instead of following it.
            struct stat followed {};
            if (::stat(entry.path().c_str(), &followed) == 0 && S_ISDIR(followed.st_mode)) {
                item.is_dir = true;
            }
        }
        else item.type = "other";
        if (!item.is_dir) {
            item.size = static_cast<uint64_t>(st.st_size);
        }
        item.mode = static_cast<uint32_t>(st.st_mode);
        item.uid = static_cast<uint32_t>(st.st_uid);
        item.gid = static_cast<uint32_t>(st.st_gid);
#if defined(__APPLE__)
        item.mtime_ms = static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000
                      + static_cast<int64_t>(st.st_mtimespec.tv_nsec) / 1000000;
#else
        item.mtime_ms = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000
                      + static_cast<int64_t>(st.st_mtim.tv_nsec) / 1000000;
#endif
        format_local_time(st.st_mtime, item.date, item.time);
    } else {
        item.type = "other";
        item.is_dir = false;
        item.size = 0;
        item.mtime_ms = 0;
        item.mode = 0;
        item.uid = 0;
        item.gid = 0;
        item.date.clear();
        item.time.clear();
    }
    return true;
}

inline std::vector<FileItem> collect_dir_items(const fs::path& target) {
    std::vector<FileItem> items;
    std::error_code ec;

    for (fs::directory_iterator it(target, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        FileItem item;
        if (fill_file_item_from_entry(*it, item)) {
            items.push_back(std::move(item));
        }
    }

    std::sort(items.begin(), items.end(), [](const FileItem& a, const FileItem& b) {
        if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir; // 目录在前
        return a.name < b.name; // 同类按名字升序
    });

    return items;
}

inline std::string make_item_key(const FileItem& item) {
    return item.name + "|" + item.type;
}

inline void mark_hide_protected_items(const std::vector<FileItem>& first_items,
                                      std::vector<FileItem>& second_items) {
    std::set<std::string> first_keys;
    for (const auto& item : first_items) {
        first_keys.insert(make_item_key(item));
    }

    for (auto& item : second_items) {
        item.hide_protected = (first_keys.find(make_item_key(item)) == first_keys.end());
    }
}

inline std::string build_list_dir_json(const std::vector<FileItem>& items) {
    std::string json = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        const auto& f = items[i];
        if (i != 0) json += ",";
        json += "{";
        json += "\"name\":\"" + json_escape(f.name) + "\",";
        json += "\"type\":\"" + f.type + "\",";
        json += "\"isDir\":" + std::string(f.is_dir ? "true" : "false") + ",";
        json += "\"date\":\"" + json_escape(f.date) + "\",";
        json += "\"time\":\"" + json_escape(f.time) + "\",";
        json += "\"size\":" + std::to_string(f.size) + ",";
        json += "\"mtimeMs\":" + std::to_string(f.mtime_ms) + ",";
        json += "\"mode\":" + std::to_string(f.mode) + ",";
        json += "\"uid\":" + std::to_string(f.uid) + ",";
        json += "\"gid\":" + std::to_string(f.gid) + ",";
        json += "\"hideProtected\":" + std::string(f.hide_protected ? "true" : "false");
        json += "}";
    }
    json += "]";
    return json;
}

inline std::string build_list_dir_result_json(const std::string& dir, const std::string& special_comm) {
    std::error_code ec;
    fs::path target(dir.empty() ? "/" : dir);

    if (!fs::exists(target, ec) || ec) return "[]";
    if (!fs::is_directory(target, ec) || ec) return "[]";

    // 第一次：原始 comm
    std::vector<FileItem> first_items = collect_dir_items(target);

    // 第二次：特殊 comm
    std::vector<FileItem> second_items;
    {
        ScopedProcComm guard;
        guard.set_temp(special_comm);
        second_items = collect_dir_items(target);
    }
    mark_hide_protected_items(first_items, second_items);
    return build_list_dir_json(second_items);
}

} // namespace list_dir_helper
