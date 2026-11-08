#pragma once

#include "file_manager_service.h"

namespace file_manager {

constexpr uint64_t kMaxArchiveIndexEntries = 100000;
constexpr size_t kMaxArchiveIndexTextBytes = 16ULL * 1024ULL * 1024ULL;

struct ArchiveIndexEntry {
    uint64_t header_index = 0;
    std::string path;
    std::string type;
    std::string symlink_target;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
};

class ArchiveService {
public:
    using Publisher = std::function<void(const JobSnapshot&)>;

    static bool isSupportedSingleArchivePath(const std::string& path);

    static bool index(const std::string& archive_path,
                      const FileVersion& version,
                      std::atomic<bool>& cancel_requested,
                      const std::function<void(uint64_t)>& progress,
                      std::vector<ArchiveIndexEntry>& entries,
                      Error& error);

    static bool scan(const std::string& archive_path,
                     const std::string& destination,
                     std::atomic<bool>& cancel_requested,
                     const Publisher& publish,
                     JobSnapshot& snapshot,
                     const ArchiveSelection* selection = nullptr);

    static bool extract(const std::string& archive_path,
                        const std::string& destination,
                        ConflictPolicy conflict,
                        std::atomic<bool>& cancel_requested,
                        const Publisher& publish,
                        JobSnapshot& snapshot,
                        const ArchiveSelection* selection = nullptr);

    static bool compress(const std::vector<std::string>& sources,
                         const std::string& output_path,
                         std::atomic<bool>& cancel_requested,
                         const Publisher& publish,
                         JobSnapshot& snapshot);
};

} // namespace file_manager
