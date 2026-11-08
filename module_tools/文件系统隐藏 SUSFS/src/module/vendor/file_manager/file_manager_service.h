#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace file_manager {

constexpr uint64_t kMaxTextFileBytes = 8ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxTransferChunkBytes = 128ULL * 1024ULL;
constexpr size_t kMaxOperationSources = 500;

struct Error {
    std::string code;
    std::string message;
    int sys_errno = 0;
};

struct FileVersion {
    uint64_t device = 0;
    uint64_t inode = 0;
    uint64_t size = 0;
    int64_t mtime_sec = 0;
    int64_t mtime_nsec = 0;
};

bool operator==(const FileVersion& a, const FileVersion& b);
bool operator!=(const FileVersion& a, const FileVersion& b);

enum class OperationType {
    Copy,
    Move,
    Delete,
    Extract,
    Properties,
    Compress,
    InstallApk,
};

enum class ConflictPolicy {
    Overwrite,
    Skip,
};

// A resolved, immutable selection. Header ordinals distinguish duplicate names;
// no browser session is needed after a file job has accepted this snapshot.
struct ArchiveSelectedEntry {
    uint64_t header_index = 0;
    std::string path;
};

struct ArchiveSelection {
    bool enabled = false;
    std::string archive_path;
    FileVersion version;
    std::string base_path;
    std::vector<ArchiveSelectedEntry> entries;
};

struct OperationSpec {
    struct PropertyChange {
        bool has_mode = false;
        uint32_t mode = 0;
        bool has_uid = false;
        uint32_t uid = 0;
        bool has_gid = false;
        uint32_t gid = 0;
        bool recursive_files = false;
        bool recursive_directories = false;
    };

    OperationType type = OperationType::Copy;
    ConflictPolicy conflict = ConflictPolicy::Skip;
    std::vector<std::string> sources;
    std::string destination;
    std::string output_path;
    PropertyChange properties;
    ArchiveSelection archive_selection;
};

struct FileProperties {
    std::string path;
    std::string name;
    std::string type;
    std::string symlink_target;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
    uint32_t mode = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string owner_name;
    std::string group_name;
    bool recursive_eligible = false;
};

struct PrincipalEntry {
    std::string name;
    uint32_t id = 0;
};

struct JobSnapshot {
    std::string id;
    std::string state = "idle";
    std::string operation;
    std::string current_path;
    std::string output_path;
    int exit_code = 0;
    std::string result_code;
    std::string result_message;
    uint64_t total_bytes = 0;
    uint64_t processed_bytes = 0;
    uint64_t total_items = 0;
    uint64_t processed_items = 0;
    uint64_t success_count = 0;
    uint64_t skipped_count = 0;
    uint64_t failed_count = 0;
    uint64_t warning_count = 0;
    std::vector<Error> errors;
    std::vector<Error> warnings;
};

class FileService {
public:
    explicit FileService(std::string special_comm = {});

    void setSpecialComm(std::string special_comm);
    bool list(const std::string& path, std::string& out_items_json, Error& error) const;
    bool makeDirectory(const std::string& path, uint32_t mode, Error& error) const;
    bool createFile(const std::string& path, uint32_t mode, uint32_t& actual_mode, Error& error) const;
    bool renamePath(const std::string& source, const std::string& target, Error& error) const;
    bool getProperties(const std::string& path, FileProperties& result, Error& error) const;
    bool listPrincipals(const std::string& path,
                        std::vector<PrincipalEntry>& users,
                        std::vector<PrincipalEntry>& groups,
                        Error& error) const;
    bool resolveUser(const std::string& value, uint32_t& uid, Error& error) const;
    bool resolveGroup(const std::string& value, uint32_t& gid, Error& error) const;
    bool isDirectory(const std::string& path) const;

    void runOperation(const OperationSpec& spec,
                      std::atomic<bool>& cancel_requested,
                      const std::function<void(const JobSnapshot&)>& publish,
                      JobSnapshot& snapshot) const;

    static bool normalizeAbsolutePath(const std::string& input, std::string& output, Error& error);
    static bool isSameOrChildPath(const std::string& parent, const std::string& candidate);

private:
    std::string m_special_comm;
};

class FileJobManager {
public:
    explicit FileJobManager(FileService& service);
    ~FileJobManager();

    bool start(const OperationSpec& spec, std::string& out_job_id, Error& error);
    bool cancel(const std::string& job_id, Error& error);
    JobSnapshot snapshot(const std::string& job_id = {}) const;
    bool isActive() const;
    // Permanent emergency stop. Safe without service locks while a request
    // is validating or a background operation is running.
    void requestStop();
    void shutdown();

private:
    void publish(const JobSnapshot& snapshot);
    void joinFinishedThread();

    FileService& m_service;
    std::mutex m_lifecycle_mu;
    mutable std::mutex m_mu;
    JobSnapshot m_snapshot;
    std::atomic<bool> m_cancel_requested{false};
    std::atomic<bool> m_stop_requested{false};
    std::thread m_worker;
};

struct TextOpenResult {
    std::string session_id;
    std::string path;
    uint64_t size = 0;
    bool has_bom = false;
    bool read_only = false;
    FileVersion version;
};

struct TextReadResult {
    std::string base64_data;
    uint64_t offset = 0;
    uint64_t next_offset = 0;
    bool eof = false;
};

class TextTransferService {
public:
    TextTransferService();
    ~TextTransferService();

    bool openText(const std::string& path, TextOpenResult& result, Error& error);
    bool readChunk(const std::string& session_id,
                   uint64_t offset,
                   size_t limit,
                   TextReadResult& result,
                   Error& error);

    bool startSave(const std::string& path,
                   const FileVersion& expected_version,
                   uint64_t expected_size,
                   bool force,
                   std::string& out_save_id,
                   Error& error);
    bool writeChunk(const std::string& save_id,
                    uint64_t offset,
                    const std::string& base64_data,
                    uint64_t& out_received,
                    Error& error);
    bool commitSave(const std::string& save_id,
                    bool force,
                    FileVersion& out_version,
                    Error& error);
    bool abortSave(const std::string& save_id, Error& error);
    bool hasActiveSave() const;
    void shutdown();

    static bool getVersion(const std::string& path, FileVersion& version, Error& error);
    static std::string encodeBase64(const uint8_t* data, size_t size);
    static bool decodeBase64(const std::string& text, std::vector<uint8_t>& out);
    static bool isValidUtf8(const uint8_t* data, size_t size);

private:
    struct ReadSession {
        std::string id;
        std::string path;
        FileVersion version;
        bool read_only = false;
        std::vector<uint8_t> snapshot;
    };

    struct SaveSession {
        std::string id;
        std::string path;
        std::string temp_path;
        FileVersion expected_version;
        uint64_t expected_size = 0;
        uint64_t received = 0;
        bool force = false;
        int fd = -1;
    };

    static void clearSaveSession(SaveSession& session, bool remove_temp);

    mutable std::mutex m_mu;
    std::unordered_map<std::string, ReadSession> m_reads;
    SaveSession m_save;
};

std::string randomHex(size_t byte_count);
std::string operationTypeName(OperationType type);

} // namespace file_manager
