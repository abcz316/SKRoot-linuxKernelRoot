#pragma once

#include "archive_service.h"

#include <memory>

namespace file_manager {

struct ArchiveBrowserStatus {
    std::string session_id;
    std::string archive_path;
    std::string state;
    uint64_t scanned_entries = 0;
    uint64_t total_entries = 0;
    uint64_t total_nodes = 0;
    FileVersion version;
    Error error;
};

struct ArchiveBrowserEntry {
    std::string id;
    std::string name;
    std::string path;
    std::string type;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
    uint64_t duplicate_index = 1;
    bool is_implicit = false;
    bool selectable = true;
};

struct ArchiveBrowserList {
    std::string session_id;
    std::string inner_path;
    uint64_t offset = 0;
    uint64_t next_offset = 0;
    uint64_t total = 0;
    bool eof = true;
    std::vector<ArchiveBrowserEntry> entries;
};

class ArchiveBrowserService {
public:
    ArchiveBrowserService();
    ~ArchiveBrowserService();
    void setSpecialComm(std::string special_comm);
    bool open(const std::string& path, ArchiveBrowserStatus& result, Error& error);
    bool status(const std::string& session_id, ArchiveBrowserStatus& result, Error& error);
    bool list(const std::string& session_id, const std::string& inner_path,
              uint64_t offset, size_t limit, ArchiveBrowserList& result, Error& error);
    bool close(const std::string& session_id, Error& error);
    bool resolveSelection(const std::string& session_id, const std::string& base_path,
                          const std::vector<std::string>& entry_ids,
                          ArchiveSelection& result, Error& error);
    bool isActive() const;
    void requestStop();
    void shutdown();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace file_manager
