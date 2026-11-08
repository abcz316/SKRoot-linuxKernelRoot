#include "file_manager_service.h"

#include "archive_service.h"
#include "list_dir_helper.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <unordered_map>

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

namespace fs = std::filesystem;

namespace file_manager {
namespace {

constexpr size_t kMaxRecordedErrors = 50;
constexpr size_t kMaxRecordedWarnings = 50;
constexpr size_t kMaxReadSessions = 8;

using WarningSink = std::function<void(std::string, std::string, int)>;

bool isActiveState(const std::string& state) {
    return state == "scanning" || state == "running" || state == "cancelling";
}

void setError(Error& error, std::string code, std::string message, int sys_errno = 0) {
    error.code = std::move(code);
    error.message = std::move(message);
    error.sys_errno = sys_errno;
}

std::string errnoMessage(const std::string& action, const std::string& path, int value) {
    return action + " failed: " + path + ": " + std::strerror(value);
}

bool lstatPath(const std::string& path, struct stat& st) {
    std::memset(&st, 0, sizeof(st));
    return ::lstat(path.c_str(), &st) == 0;
}

DIR* openDirectoryNoFollow(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nullptr;
    DIR* dir = ::fdopendir(fd);
    if (!dir) {
        int value = errno;
        ::close(fd);
        errno = value;
    }
    return dir;
}

int renameNoReplace(const std::string& source, const std::string& target) {
#if defined(__NR_renameat2)
    return static_cast<int>(::syscall(__NR_renameat2, AT_FDCWD, source.c_str(),
                                      AT_FDCWD, target.c_str(), RENAME_NOREPLACE));
#else
    (void)source;
    (void)target;
    errno = ENOSYS;
    return -1;
#endif
}

std::string parentPath(const std::string& path);

bool destinationIsInsideDirectory(const std::string& source, const std::string& destination) {
    struct stat source_stat {};
    if (!lstatPath(source, source_stat) || !S_ISDIR(source_stat.st_mode)) return false;

    std::array<char, PATH_MAX + 1> resolved {};
    if (!::realpath(destination.c_str(), resolved.data())) return false;
    std::string current(resolved.data());
    while (true) {
        struct stat current_stat {};
        if (::stat(current.c_str(), &current_stat) == 0
            && current_stat.st_dev == source_stat.st_dev
            && current_stat.st_ino == source_stat.st_ino) return true;
        if (current == "/") break;
        current = parentPath(current);
    }
    return false;
}

FileVersion versionFromStat(const struct stat& st) {
    FileVersion version;
    version.device = static_cast<uint64_t>(st.st_dev);
    version.inode = static_cast<uint64_t>(st.st_ino);
    version.size = static_cast<uint64_t>(std::max<off_t>(0, st.st_size));
#if defined(__APPLE__)
    version.mtime_sec = st.st_mtimespec.tv_sec;
    version.mtime_nsec = st.st_mtimespec.tv_nsec;
#else
    version.mtime_sec = st.st_mtim.tv_sec;
    version.mtime_nsec = st.st_mtim.tv_nsec;
#endif
    return version;
}

std::string parentPath(const std::string& path) {
    fs::path value(path);
    std::string parent = value.parent_path().string();
    return parent.empty() ? "/" : parent;
}

std::string baseName(const std::string& path) {
    return fs::path(path).filename().string();
}

std::string joinPath(const std::string& parent, const std::string& name) {
    return (fs::path(parent) / name).lexically_normal().string();
}

int64_t mtimeMsFromStat(const struct stat& st) {
#if defined(__APPLE__)
    return static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000
         + static_cast<int64_t>(st.st_mtimespec.tv_nsec) / 1000000;
#else
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000
         + static_cast<int64_t>(st.st_mtim.tv_nsec) / 1000000;
#endif
}

std::string fileTypeFromMode(mode_t mode) {
    if (S_ISREG(mode)) return "file";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISCHR(mode)) return "character";
    if (S_ISBLK(mode)) return "block";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISSOCK(mode)) return "socket";
    return "other";
}

bool parseUnsignedId(const std::string& value, uint32_t& result) {
    if (value.empty() || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        })) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || !end || *end != '\0'
        || parsed > std::numeric_limits<uint32_t>::max()) return false;
    result = static_cast<uint32_t>(parsed);
    return true;
}

std::string userNameFor(uint32_t uid) {
    struct passwd value {};
    struct passwd* found = nullptr;
    std::array<char, 4096> buffer {};
    if (::getpwuid_r(static_cast<uid_t>(uid), &value, buffer.data(), buffer.size(), &found) == 0
        && found && found->pw_name) return found->pw_name;
    return {};
}

std::mutex& groupLookupMutex() {
    static std::mutex mutex;
    return mutex;
}

std::string groupNameFor(uint32_t gid) {
    std::lock_guard<std::mutex> lock(groupLookupMutex());
    struct group* found = ::getgrgid(static_cast<gid_t>(gid));
    if (found && found->gr_name) return found->gr_name;
    return {};
}

void parseIdentityFile(const char* path, size_t id_column,
                       std::map<uint32_t, std::string>& output) {
    std::ifstream stream(path);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty() || line.front() == '#') continue;
        std::vector<std::string> fields;
        std::stringstream parser(line);
        std::string field;
        while (std::getline(parser, field, ':')) fields.push_back(field);
        if (fields.size() <= id_column || fields[0].empty()) continue;
        uint32_t id = 0;
        if (parseUnsignedId(fields[id_column], id)) output.emplace(id, fields[0]);
    }
}

void addAndroidCorePrincipals(std::map<uint32_t, std::string>& output) {
    static const std::pair<uint32_t, const char*> kCore[] = {
        {0, "root"}, {1000, "system"}, {1001, "radio"}, {1002, "bluetooth"},
        {1003, "graphics"}, {1004, "input"}, {1005, "audio"}, {1006, "camera"},
        {1007, "log"}, {1010, "wifi"}, {1011, "adb"}, {1012, "install"},
        {1013, "media"}, {1015, "sdcard_rw"}, {1023, "media_rw"}, {2000, "shell"},
        {9997, "everybody"}, {9999, "nobody"},
    };
    for (const auto& entry : kCore) output.emplace(entry.first, entry.second);
}

std::vector<PrincipalEntry> buildPrincipalList(bool users, uint32_t current_id) {
    std::map<uint32_t, std::string> entries;
    addAndroidCorePrincipals(entries);
    static const char* kRoots[] = {"/etc", "/system/etc", "/system_ext/etc",
                                   "/vendor/etc", "/odm/etc", "/product/etc"};
    for (const char* root : kRoots) {
        parseIdentityFile((std::string(root) + (users ? "/passwd" : "/group")).c_str(),
                          users ? 2 : 2, entries);
    }
    const std::string current_name = users ? userNameFor(current_id) : groupNameFor(current_id);
    if (!current_name.empty()) entries[current_id] = current_name;
    else entries.emplace(current_id, std::to_string(current_id));

    std::vector<PrincipalEntry> result;
    result.reserve(entries.size());
    for (const auto& item : entries) result.push_back({item.second, item.first});
    return result;
}

bool writeAll(int fd, const uint8_t* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t value = ::write(fd, data + written, size - written);
        if (value > 0) {
            written += static_cast<size_t>(value);
            continue;
        }
        if (value < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool isVirtualTextFilesystem(const struct statfs& filesystem) {
    return filesystem.f_type == PROC_SUPER_MAGIC || filesystem.f_type == SYSFS_MAGIC;
}

bool checkTextSaveFilesystem(const std::string& path, Error& error) {
    struct statfs filesystem {};
    if (::statfs(path.c_str(), &filesystem) != 0) {
        const int value = errno;
        setError(error, "STAT_FAILED", errnoMessage("statfs", path, value), value);
        return false;
    }
    if (isVirtualTextFilesystem(filesystem)) {
        setError(error, "READ_ONLY_FILE", "Kernel virtual files are read-only in the text editor", EROFS);
        return false;
    }
    return true;
}

struct TextFileReadInfo {
    FileVersion version;
    bool read_only = false;
};

bool readAllFile(const std::string& path, uint64_t max_size, std::vector<uint8_t>& out,
                 Error& error, TextFileReadInfo* info = nullptr) {
    struct stat st {};
    if (!lstatPath(path, st)) {
        int value = errno;
        setError(error, "STAT_FAILED", errnoMessage("lstat", path, value), value);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        setError(error, "NOT_REGULAR_FILE", "Path is not a regular file: " + path);
        return false;
    }
    // Nonblocking also prevents a replaced FIFO or a streaming proc entry from
    // indefinitely holding the file broker while opening/reading it.
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        int value = errno;
        setError(error, "OPEN_FAILED", errnoMessage("open", path, value), value);
        return false;
    }
    if (::fstat(fd, &st) != 0) {
        const int value = errno;
        ::close(fd);
        setError(error, "STAT_FAILED", errnoMessage("fstat", path, value), value);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        ::close(fd);
        setError(error, "NOT_REGULAR_FILE", "Path is not a regular file: " + path);
        return false;
    }
    struct statfs filesystem {};
    if (::fstatfs(fd, &filesystem) != 0) {
        const int value = errno;
        ::close(fd);
        setError(error, "STAT_FAILED", errnoMessage("fstatfs", path, value), value);
        return false;
    }
    const bool read_only = isVirtualTextFilesystem(filesystem);
    const FileVersion version = versionFromStat(st);
    if (!read_only && (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > max_size)) {
        ::close(fd);
        setError(error, "TEXT_TOO_LARGE", "Text file exceeds the configured size limit");
        return false;
    }
    out.clear();
    out.reserve(static_cast<size_t>(std::min(version.size, max_size)));
    std::array<uint8_t, 64 * 1024> buffer {};
    for (;;) {
        const uint64_t remaining = max_size - out.size();
        // Probe one byte past the limit to distinguish exact-limit files from
        // oversized streams without trusting procfs/sysfs st_size.
        const size_t requested = remaining < buffer.size()
            ? static_cast<size_t>(remaining + 1) : buffer.size();
        const ssize_t value = ::read(fd, buffer.data(), requested);
        if (value > 0) {
            if (static_cast<uint64_t>(value) > remaining) {
                ::close(fd);
                setError(error, "TEXT_TOO_LARGE", "Text file exceeds the configured size limit");
                return false;
            }
            out.insert(out.end(), buffer.data(), buffer.data() + value);
            continue;
        }
        if (value == 0) break;
        if (errno == EINTR) continue;
        int saved = errno;
        ::close(fd);
        setError(error, "READ_FAILED", errnoMessage("read", path, saved), saved);
        return false;
    }
    struct stat final_stat {};
    if (::fstat(fd, &final_stat) != 0) {
        const int value = errno;
        ::close(fd);
        setError(error, "STAT_FAILED", errnoMessage("fstat", path, value), value);
        return false;
    }
    ::close(fd);
    if (!read_only && (versionFromStat(final_stat) != version || version.size != out.size())) {
        setError(error, "FILE_CHANGED", "The file changed while it was being read", EBUSY);
        return false;
    }
    if (info) *info = {version, read_only};
    return true;
}

void reportMetadataWarning(const WarningSink& warning,
                           const std::string& action,
                           const std::string& path,
                           int value) {
    if (warning) warning("METADATA_FAILED", errnoMessage(action, path, value), value);
}

void bestEffortCopyXattrs(const std::string& source,
                          const std::string& target,
                          bool symlink_target,
                          const WarningSink& warning) {
    ssize_t size = ::llistxattr(source.c_str(), nullptr, 0);
    if (size < 0) {
        reportMetadataWarning(warning, "llistxattr", source, errno);
        return;
    }
    if (size == 0) return;
    std::vector<char> names(static_cast<size_t>(size));
    size = ::llistxattr(source.c_str(), names.data(), names.size());
    if (size < 0) {
        reportMetadataWarning(warning, "llistxattr", source, errno);
        return;
    }
    if (size == 0) return;

    size_t offset = 0;
    while (offset < static_cast<size_t>(size)) {
        const char* name = names.data() + offset;
        size_t name_len = std::strlen(name);
        if (name_len == 0) break;
        ssize_t value_size = ::lgetxattr(source.c_str(), name, nullptr, 0);
        if (value_size < 0) {
            reportMetadataWarning(warning, "lgetxattr", source + ":" + name, errno);
            offset += name_len + 1;
            continue;
        }
        std::vector<uint8_t> value(static_cast<size_t>(value_size));
        ssize_t read_size = value_size == 0 ? 0
            : ::lgetxattr(source.c_str(), name, value.data(), value.size());
        if (read_size != value_size) {
            reportMetadataWarning(warning, "lgetxattr", source + ":" + name,
                                  read_size < 0 ? errno : EIO);
            offset += name_len + 1;
            continue;
        }
        int result = symlink_target
            ? ::lsetxattr(target.c_str(), name, value.data(), value.size(), 0)
            : ::setxattr(target.c_str(), name, value.data(), value.size(), 0);
        if (result != 0) {
            reportMetadataWarning(warning, "setxattr", target + ":" + name, errno);
        }
        offset += name_len + 1;
    }
}

void bestEffortApplyMetadata(const std::string& source,
                             const std::string& target,
                             const struct stat& source_stat,
                             bool target_is_symlink,
                             const WarningSink& warning = {}) {
    if (::lchown(target.c_str(), source_stat.st_uid, source_stat.st_gid) != 0) {
        reportMetadataWarning(warning, "lchown", target, errno);
    }
    if (!target_is_symlink) {
        if (::chmod(target.c_str(), source_stat.st_mode & 07777) != 0) {
            reportMetadataWarning(warning, "chmod", target, errno);
        }
    }
#if defined(__APPLE__)
    timespec times[2] = {source_stat.st_atimespec, source_stat.st_mtimespec};
#else
    timespec times[2] = {source_stat.st_atim, source_stat.st_mtim};
#endif
    if (::utimensat(AT_FDCWD, target.c_str(), times,
                    target_is_symlink ? AT_SYMLINK_NOFOLLOW : 0) != 0) {
        reportMetadataWarning(warning, "utimensat", target, errno);
    }
    bestEffortCopyXattrs(source, target, target_is_symlink, warning);
}

struct OperationRunner {
    struct ScanTotals {
        uint64_t items = 0;
        uint64_t bytes = 0;
    };

    const OperationSpec& spec;
    std::atomic<bool>& cancel;
    const std::function<void(const JobSnapshot&)>& publish;
    JobSnapshot& snapshot;
    std::unordered_map<std::string, ScanTotals> scan_totals;

    bool cancelled() const {
        return cancel.load(std::memory_order_acquire);
    }

    void emit() const {
        publish(snapshot);
    }

    void recordError(std::string code, std::string message, int value, bool failed = true) {
        if (failed) snapshot.failed_count++;
        if (snapshot.errors.size() < kMaxRecordedErrors) {
            snapshot.errors.push_back({std::move(code), std::move(message), value});
        }
        emit();
    }

    void recordWarning(std::string code, std::string message, int value) {
        snapshot.warning_count++;
        if (snapshot.warnings.size() < kMaxRecordedWarnings) {
            snapshot.warnings.push_back({std::move(code), std::move(message), value});
        }
        emit();
    }

    WarningSink metadataWarningSink() {
        return [this](std::string code, std::string message, int value) {
            recordWarning(std::move(code), std::move(message), value);
        };
    }

    void recordSkip(const std::string& path) {
        snapshot.current_path = path;
        snapshot.skipped_count++;
        snapshot.processed_items++;
        emit();
    }

    void recordTreeSkip(const std::string& path) {
        auto it = scan_totals.find(path);
        const uint64_t items = it == scan_totals.end() ? 1 : it->second.items;
        snapshot.current_path = path;
        snapshot.skipped_count += items;
        snapshot.processed_items += items;
        emit();
    }

    void recordAtomicMove(const std::string& path, const struct stat& st) {
        auto it = scan_totals.find(path);
        const uint64_t items = it == scan_totals.end() ? 1 : it->second.items;
        const uint64_t bytes = it == scan_totals.end()
            ? (S_ISREG(st.st_mode) ? static_cast<uint64_t>(std::max<off_t>(0, st.st_size)) : 0)
            : it->second.bytes;
        snapshot.current_path = path;
        snapshot.processed_items += items;
        snapshot.processed_bytes += bytes;
        snapshot.success_count += items;
        emit();
    }

    bool scan(const std::string& path) {
        if (cancelled()) return false;
        const uint64_t items_before = snapshot.total_items;
        const uint64_t bytes_before = snapshot.total_bytes;
        struct stat st {};
        if (!lstatPath(path, st)) {
            int value = errno;
            recordError("SCAN_FAILED", errnoMessage("lstat", path, value), value, false);
            return false;
        }
        snapshot.total_items++;
        if (S_ISREG(st.st_mode)) snapshot.total_bytes += static_cast<uint64_t>(std::max<off_t>(0, st.st_size));
        if (!S_ISDIR(st.st_mode)) {
            scan_totals[path] = {snapshot.total_items - items_before,
                                 snapshot.total_bytes - bytes_before};
            return true;
        }

        DIR* dir = openDirectoryNoFollow(path);
        if (!dir) {
            int value = errno;
            recordError("SCAN_FAILED", errnoMessage("opendir", path, value), value, false);
            return false;
        }
        while (!cancelled()) {
            errno = 0;
            dirent* entry = ::readdir(dir);
            if (!entry) break;
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
            scan(joinPath(path, entry->d_name));
        }
        ::closedir(dir);
        scan_totals[path] = {snapshot.total_items - items_before,
                             snapshot.total_bytes - bytes_before};
        return !cancelled();
    }

    bool removeTree(const std::string& path, bool count_progress) {
        if (cancelled()) return false;
        struct stat st {};
        if (!lstatPath(path, st)) {
            if (errno == ENOENT) return true;
            int value = errno;
            recordError("DELETE_FAILED", errnoMessage("lstat", path, value), value);
            return false;
        }

        snapshot.current_path = path;
        if (S_ISDIR(st.st_mode)) {
            DIR* dir = openDirectoryNoFollow(path);
            if (!dir) {
                int value = errno;
                recordError("DELETE_FAILED", errnoMessage("opendir", path, value), value);
                return false;
            }
            bool ok = true;
            while (!cancelled()) {
                errno = 0;
                dirent* entry = ::readdir(dir);
                if (!entry) break;
                if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
                if (!removeTree(joinPath(path, entry->d_name), count_progress)) ok = false;
            }
            ::closedir(dir);
            if (cancelled()) return false;
            if (::rmdir(path.c_str()) != 0) {
                int value = errno;
                recordError("DELETE_FAILED", errnoMessage("rmdir", path, value), value);
                return false;
            }
            if (count_progress) {
                snapshot.processed_items++;
                snapshot.success_count++;
                emit();
            }
            return ok;
        }

        if (::unlink(path.c_str()) != 0) {
            int value = errno;
            recordError("DELETE_FAILED", errnoMessage("unlink", path, value), value);
            return false;
        }
        if (count_progress) {
            snapshot.processed_items++;
            snapshot.success_count++;
            if (S_ISREG(st.st_mode)) snapshot.processed_bytes += static_cast<uint64_t>(std::max<off_t>(0, st.st_size));
            emit();
        }
        return true;
    }

    bool prepareTarget(const std::string& source,
                       const std::string& target,
                       bool source_is_dir,
                       bool& merge_directory) {
        merge_directory = false;
        struct stat dst {};
        if (!lstatPath(target, dst)) {
            if (errno == ENOENT) return true;
            int value = errno;
            recordError("TARGET_STAT_FAILED", errnoMessage("lstat", target, value), value);
            return false;
        }
        if (source_is_dir && S_ISDIR(dst.st_mode)) {
            merge_directory = true;
            return true;
        }
        if (spec.conflict == ConflictPolicy::Skip) {
            recordTreeSkip(source);
            return false;
        }
        // rename(2) atomically replaces non-directory targets. Keep the old
        // target in place until the temporary file or symlink is complete.
        if (!source_is_dir && !S_ISDIR(dst.st_mode)) return true;
        return removeTree(target, false);
    }

    bool copyRegular(const std::string& source, const std::string& target, const struct stat& source_stat) {
        bool merge = false;
        if (!prepareTarget(source, target, false, merge)) return spec.conflict == ConflictPolicy::Skip;

        int input = ::open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (input < 0) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("open", source, value), value);
            return false;
        }

        const std::string temp = joinPath(parentPath(target), ".skroot-copy-" + randomHex(8));
        int output = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (output < 0) {
            int value = errno;
            ::close(input);
            recordError("COPY_FAILED", errnoMessage("create", temp, value), value);
            return false;
        }

        bool ok = true;
        std::array<uint8_t, 64 * 1024> buffer {};
        snapshot.current_path = source;
        while (!cancelled()) {
            ssize_t value = ::read(input, buffer.data(), buffer.size());
            if (value > 0) {
                if (!writeAll(output, buffer.data(), static_cast<size_t>(value))) {
                    int saved = errno;
                    recordError("COPY_FAILED", errnoMessage("write", temp, saved), saved);
                    ok = false;
                    break;
                }
                snapshot.processed_bytes += static_cast<uint64_t>(value);
                emit();
                continue;
            }
            if (value == 0) break;
            if (errno == EINTR) continue;
            int saved = errno;
            recordError("COPY_FAILED", errnoMessage("read", source, saved), saved);
            ok = false;
            break;
        }
        if (cancelled()) ok = false;

        if (ok) {
            if (::fsync(output) != 0) {
                int saved = errno;
                recordError("COPY_FAILED", errnoMessage("fsync", temp, saved), saved);
                ok = false;
            }
        }
        ::close(input);
        ::close(output);

        if (ok) {
            bestEffortApplyMetadata(source, temp, source_stat, false, metadataWarningSink());
            if (::rename(temp.c_str(), target.c_str()) != 0) {
                int saved = errno;
                recordError("COPY_FAILED", errnoMessage("rename", target, saved), saved);
                ok = false;
            }
        }
        if (!ok) (void)::unlink(temp.c_str());
        if (ok) {
            snapshot.processed_items++;
            snapshot.success_count++;
            emit();
        }
        return ok;
    }

    bool copySymlink(const std::string& source, const std::string& target, const struct stat& source_stat) {
        bool merge = false;
        if (!prepareTarget(source, target, false, merge)) return spec.conflict == ConflictPolicy::Skip;
        std::vector<char> link_value(static_cast<size_t>(std::max<off_t>(source_stat.st_size + 1, PATH_MAX)) + 1, 0);
        ssize_t size = ::readlink(source.c_str(), link_value.data(), link_value.size() - 1);
        if (size < 0) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("readlink", source, value), value);
            return false;
        }
        link_value[static_cast<size_t>(size)] = '\0';
        const std::string temp = joinPath(parentPath(target), ".skroot-link-" + randomHex(8));
        if (::symlink(link_value.data(), temp.c_str()) != 0) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("symlink", temp, value), value);
            return false;
        }
        bestEffortApplyMetadata(source, temp, source_stat, true, metadataWarningSink());
        if (::rename(temp.c_str(), target.c_str()) != 0) {
            int value = errno;
            (void)::unlink(temp.c_str());
            recordError("COPY_FAILED", errnoMessage("rename", target, value), value);
            return false;
        }
        snapshot.current_path = source;
        snapshot.processed_items++;
        snapshot.success_count++;
        emit();
        return true;
    }

    bool copyDirectory(const std::string& source, const std::string& target, const struct stat& source_stat) {
        bool merge = false;
        if (!prepareTarget(source, target, true, merge)) return spec.conflict == ConflictPolicy::Skip;
        if (!merge && ::mkdir(target.c_str(), source_stat.st_mode & 07777) != 0) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("mkdir", target, value), value);
            return false;
        }

        DIR* dir = openDirectoryNoFollow(source);
        if (!dir) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("opendir", source, value), value);
            return false;
        }
        bool ok = true;
        while (!cancelled()) {
            errno = 0;
            dirent* entry = ::readdir(dir);
            if (!entry) break;
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
            if (!copyPath(joinPath(source, entry->d_name), joinPath(target, entry->d_name))) ok = false;
        }
        ::closedir(dir);
        if (cancelled()) return false;
        bestEffortApplyMetadata(source, target, source_stat, false, metadataWarningSink());
        snapshot.current_path = source;
        snapshot.processed_items++;
        if (ok) snapshot.success_count++;
        emit();
        return ok;
    }

    bool copyPath(const std::string& source, const std::string& target) {
        if (cancelled()) return false;
        struct stat source_stat {};
        if (!lstatPath(source, source_stat)) {
            int value = errno;
            recordError("COPY_FAILED", errnoMessage("lstat", source, value), value);
            return false;
        }
        if (S_ISREG(source_stat.st_mode)) return copyRegular(source, target, source_stat);
        if (S_ISDIR(source_stat.st_mode)) return copyDirectory(source, target, source_stat);
        if (S_ISLNK(source_stat.st_mode)) return copySymlink(source, target, source_stat);
        recordError("UNSUPPORTED_FILE_TYPE", "Unsupported file type: " + source, 0);
        return false;
    }

    bool verifyCopyTree(const std::string& source, const std::string& target) {
        if (cancelled()) return false;
        struct stat source_stat {};
        struct stat target_stat {};
        if (!lstatPath(source, source_stat) || !lstatPath(target, target_stat)) {
            int value = errno;
            recordError("VERIFY_FAILED", errnoMessage("lstat", target, value), value);
            return false;
        }
        if ((source_stat.st_mode & S_IFMT) != (target_stat.st_mode & S_IFMT)) {
            recordError("VERIFY_FAILED", "Copied file type does not match: " + target, EIO);
            return false;
        }
        if (S_ISREG(source_stat.st_mode)) {
            if (source_stat.st_size != target_stat.st_size) {
                recordError("VERIFY_FAILED", "Copied file size does not match: " + target, EIO);
                return false;
            }
            return true;
        }
        if (S_ISLNK(source_stat.st_mode)) {
            std::vector<char> source_value(PATH_MAX + 1, 0);
            std::vector<char> target_value(PATH_MAX + 1, 0);
            ssize_t source_size = ::readlink(source.c_str(), source_value.data(), PATH_MAX);
            ssize_t target_size = ::readlink(target.c_str(), target_value.data(), PATH_MAX);
            if (source_size < 0 || target_size < 0 || source_size != target_size
                || std::memcmp(source_value.data(), target_value.data(), static_cast<size_t>(source_size)) != 0) {
                int value = source_size < 0 || target_size < 0 ? errno : EIO;
                recordError("VERIFY_FAILED", "Copied symlink does not match: " + target, value);
                return false;
            }
            return true;
        }
        if (!S_ISDIR(source_stat.st_mode)) return true;

        DIR* dir = openDirectoryNoFollow(source);
        if (!dir) {
            int value = errno;
            recordError("VERIFY_FAILED", errnoMessage("opendir", source, value), value);
            return false;
        }
        bool ok = true;
        while (!cancelled()) {
            dirent* entry = ::readdir(dir);
            if (!entry) break;
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
            if (!verifyCopyTree(joinPath(source, entry->d_name), joinPath(target, entry->d_name))) {
                ok = false;
                break;
            }
        }
        ::closedir(dir);
        return ok && !cancelled();
    }

    bool movePath(const std::string& source, const std::string& target) {
        if (cancelled()) return false;
        struct stat source_stat {};
        if (!lstatPath(source, source_stat)) {
            int value = errno;
            recordError("MOVE_FAILED", errnoMessage("lstat", source, value), value);
            return false;
        }

        struct stat target_stat {};
        bool target_exists = lstatPath(target, target_stat);
        if (!target_exists && errno != ENOENT) {
            int value = errno;
            recordError("MOVE_FAILED", errnoMessage("lstat", target, value), value);
            return false;
        }

        if (!target_exists) {
            if (::rename(source.c_str(), target.c_str()) == 0) {
                recordAtomicMove(source, source_stat);
                return true;
            }
            if (errno != EXDEV) {
                int value = errno;
                recordError("MOVE_FAILED", errnoMessage("rename", source, value), value);
                return false;
            }
            bool copied = copyPath(source, target);
            if (!copied || cancelled()) return false;
            if (!verifyCopyTree(source, target)) return false;
            return removeTree(source, false);
        }

        if (S_ISDIR(source_stat.st_mode) && S_ISDIR(target_stat.st_mode)) {
            DIR* dir = openDirectoryNoFollow(source);
            if (!dir) {
                int value = errno;
                recordError("MOVE_FAILED", errnoMessage("opendir", source, value), value);
                return false;
            }
            bool ok = true;
            while (!cancelled()) {
                dirent* entry = ::readdir(dir);
                if (!entry) break;
                if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
                if (!movePath(joinPath(source, entry->d_name), joinPath(target, entry->d_name))) ok = false;
            }
            ::closedir(dir);
            if (!cancelled()) {
                bestEffortApplyMetadata(source, target, source_stat, false, metadataWarningSink());
            }
            if (!cancelled() && ::rmdir(source.c_str()) == 0) {
                snapshot.current_path = source;
                snapshot.processed_items++;
                if (ok) snapshot.success_count++;
                emit();
            } else if (!cancelled() && errno != ENOTEMPTY && errno != EEXIST) {
                int value = errno;
                recordError("MOVE_FAILED", errnoMessage("rmdir", source, value), value);
                ok = false;
            }
            return ok;
        }

        if (spec.conflict == ConflictPolicy::Skip) {
            recordTreeSkip(source);
            return true;
        }
        if (!S_ISDIR(source_stat.st_mode) && !S_ISDIR(target_stat.st_mode)) {
            if (::rename(source.c_str(), target.c_str()) == 0) {
                recordAtomicMove(source, source_stat);
                return true;
            }
            if (errno != EXDEV) {
                int value = errno;
                recordError("MOVE_FAILED", errnoMessage("rename", source, value), value);
                return false;
            }
            bool copied = copyPath(source, target);
            if (!copied || cancelled()) return false;
            if (!verifyCopyTree(source, target)) return false;
            return removeTree(source, false);
        }
        if (!removeTree(target, false)) return false;
        if (::rename(source.c_str(), target.c_str()) == 0) {
            recordAtomicMove(source, source_stat);
            return true;
        }
        if (errno != EXDEV) {
            int value = errno;
            recordError("MOVE_FAILED", errnoMessage("rename", source, value), value);
            return false;
        }
        bool copied = copyPath(source, target);
        if (!copied || cancelled()) return false;
        if (!verifyCopyTree(source, target)) return false;
        return removeTree(source, false);
    }
};

struct PropertyRunner {
    const OperationSpec& spec;
    std::atomic<bool>& cancel;
    const std::function<void(const JobSnapshot&)>& publish;
    JobSnapshot& snapshot;

    bool cancelled() const { return cancel.load(std::memory_order_acquire); }
    void emit() const { publish(snapshot); }

    void recordError(const std::string& path, const std::string& action, int value) {
        snapshot.failed_count++;
        if (snapshot.errors.size() < kMaxRecordedErrors) {
            snapshot.errors.push_back({"PROPERTIES_FAILED", errnoMessage(action, path, value), value});
        }
        emit();
    }

    void recordWarning(const std::string& path, std::string message) {
        snapshot.warning_count++;
        if (snapshot.warnings.size() < kMaxRecordedWarnings) {
            snapshot.warnings.push_back({"SYMLINK_MODE_SKIPPED", std::move(message), 0});
        }
        snapshot.current_path = path;
        emit();
    }

    bool selected(const struct stat& st, bool root) const {
        if (root) return true;
        return S_ISDIR(st.st_mode) ? spec.properties.recursive_directories
                                   : spec.properties.recursive_files;
    }

    bool scanTree(const std::string& path, bool root) {
        if (cancelled()) return false;
        struct stat st {};
        if (!lstatPath(path, st)) {
            recordError(path, "lstat", errno);
            return false;
        }
        if (selected(st, root)) snapshot.total_items++;
        snapshot.current_path = path;
        emit();
        if (!S_ISDIR(st.st_mode)
            || (!spec.properties.recursive_files && !spec.properties.recursive_directories)) return true;

        DIR* dir = openDirectoryNoFollow(path);
        if (!dir) {
            recordError(path, "opendir", errno);
            return false;
        }
        bool ok = true;
        while (!cancelled()) {
            errno = 0;
            dirent* entry = ::readdir(dir);
            if (!entry) {
                if (errno != 0) {
                    recordError(path, "readdir", errno);
                    ok = false;
                }
                break;
            }
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
            if (!scanTree(joinPath(path, entry->d_name), false)) ok = false;
        }
        ::closedir(dir);
        return ok && !cancelled();
    }

    bool applyOne(const std::string& path, const struct stat& st) {
        if (cancelled()) return false;
        snapshot.current_path = path;
        bool failed = false;
        bool changed = false;
        bool mode_skipped = false;

        if (spec.properties.has_uid || spec.properties.has_gid) {
            const uid_t uid = spec.properties.has_uid
                ? static_cast<uid_t>(spec.properties.uid) : static_cast<uid_t>(-1);
            const gid_t gid = spec.properties.has_gid
                ? static_cast<gid_t>(spec.properties.gid) : static_cast<gid_t>(-1);
            if (::lchown(path.c_str(), uid, gid) != 0) {
                recordError(path, "lchown", errno);
                failed = true;
            } else {
                changed = true;
                if (!spec.properties.has_mode && !S_ISLNK(st.st_mode)
                    && ::chmod(path.c_str(), st.st_mode & 07777) != 0) {
                    recordError(path, "restore chmod", errno);
                    failed = true;
                }
            }
        }

        if (spec.properties.has_mode) {
            if (S_ISLNK(st.st_mode)) {
                mode_skipped = true;
                recordWarning(path, "Symbolic link mode was left unchanged: " + path);
            } else if (::chmod(path.c_str(), static_cast<mode_t>(spec.properties.mode & 07777)) != 0) {
                recordError(path, "chmod", errno);
                failed = true;
            } else {
                changed = true;
            }
        }

        snapshot.processed_items++;
        if (failed) {
            // failed_count is recorded with the detailed error above.
        } else if (changed) {
            snapshot.success_count++;
        } else if (mode_skipped) {
            snapshot.skipped_count++;
        }
        emit();
        return !failed;
    }

    bool applyTree(const std::string& path, bool root) {
        if (cancelled()) return false;
        struct stat st {};
        if (!lstatPath(path, st)) {
            recordError(path, "lstat", errno);
            return false;
        }
        bool ok = true;
        if (S_ISDIR(st.st_mode)
            && (spec.properties.recursive_files || spec.properties.recursive_directories)) {
            DIR* dir = openDirectoryNoFollow(path);
            if (!dir) {
                recordError(path, "opendir", errno);
                return false;
            }
            while (!cancelled()) {
                errno = 0;
                dirent* entry = ::readdir(dir);
                if (!entry) {
                    if (errno != 0) {
                        recordError(path, "readdir", errno);
                        ok = false;
                    }
                    break;
                }
                if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
                if (!applyTree(joinPath(path, entry->d_name), false)) ok = false;
            }
            ::closedir(dir);
        }
        if (cancelled()) return false;
        if (selected(st, root) && !applyOne(path, st)) ok = false;
        return ok;
    }
};

bool fsyncParent(const std::string& path) {
    int fd = ::open(parentPath(path).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

std::string zipArchiveStem(const std::vector<std::string>& sources) {
    if (sources.empty()) return "archive";
    std::string name = baseName(sources.front());
    const std::string lower = [&]() {
        std::string value = name;
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    }();
    if (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".zip") == 0) {
        name.resize(name.size() - 4);
    }
    return name.empty() ? "archive" : name;
}

void publishJob(const std::function<void(const JobSnapshot&)>& publish,
               JobSnapshot& snapshot) {
    publish(snapshot);
}

std::string sanitizeApkOutput(std::string value, const std::string& apk_path) {
    size_t offset = 0;
    while ((offset = value.find(apk_path, offset)) != std::string::npos) {
        value.replace(offset, apk_path.size(), "<apk>");
        offset += 5;
    }
    std::istringstream lines(value);
    std::string line;
    std::string summary;
    size_t count = 0;
    while (std::getline(lines, line) && count < 6) {
        while (!line.empty() && (line.back() == '\r' || std::isspace(static_cast<unsigned char>(line.back())))) {
            line.pop_back();
        }
        size_t start = 0;
        while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        line.erase(0, start);
        if (line.empty() || line.rfind("at ", 0) == 0) continue;
        if (!summary.empty()) summary += " · ";
        summary += line;
        ++count;
    }
    if (summary.empty()) summary = value;
    if (summary.size() > 1536) summary.resize(1536);
    return summary;
}

int apkInstallTimeoutSeconds() {
#if !defined(__ANDROID__)
    const char* test_value = ::getenv("SKROOT_TEST_APK_TIMEOUT_SECONDS");
    if (test_value && *test_value) {
        char* end = nullptr;
        const long parsed = std::strtol(test_value, &end, 10);
        if (end && *end == '\0' && parsed > 0 && parsed <= 600) return static_cast<int>(parsed);
    }
#endif
    return 600;
}

struct ApkInstallAttempt {
    int status = 1 << 8;
    bool cancelled = false;
    bool timed_out = false;
    bool launched = false;
    std::string output;
};

void appendApkOutput(std::string& output, const char* data, size_t size) {
    if (size == 0) return;
    output.append(data, size);
    if (output.size() > 8192) output.erase(0, output.size() - 8192);
}

bool runApkInstallAttempt(const std::string& apk_path,
                          const std::string& apk_size,
                          std::atomic<bool>& cancel,
                          ApkInstallAttempt& result) {
    const int apk_input = ::open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (apk_input < 0) {
        result.output = "Failed to open APK for streaming: " + std::string(std::strerror(errno));
        return false;
    }
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    if (::pipe2(input_pipe, O_CLOEXEC) != 0 || ::pipe2(output_pipe, O_CLOEXEC) != 0) {
        const int value = errno;
        ::close(apk_input);
        if (input_pipe[0] >= 0) ::close(input_pipe[0]);
        if (input_pipe[1] >= 0) ::close(input_pipe[1]);
        if (output_pipe[0] >= 0) ::close(output_pipe[0]);
        if (output_pipe[1] >= 0) ::close(output_pipe[1]);
        result.output = "pipe failed: " + std::string(std::strerror(value));
        return false;
    }
    const pid_t child = ::fork();
    if (child < 0) {
        const int value = errno;
        ::close(apk_input);
        ::close(input_pipe[0]);
        ::close(input_pipe[1]);
        ::close(output_pipe[0]);
        ::close(output_pipe[1]);
        result.output = "fork failed: " + std::string(std::strerror(value));
        return false;
    }
    if (child == 0) {
        (void)::setpgid(0, 0);
        (void)::dup2(input_pipe[0], STDIN_FILENO);
        (void)::dup2(output_pipe[1], STDOUT_FILENO);
        (void)::dup2(output_pipe[1], STDERR_FILENO);
        ::close(apk_input);
        ::close(input_pipe[0]);
        ::close(input_pipe[1]);
        ::close(output_pipe[0]);
        ::close(output_pipe[1]);

        const char* test_installer = nullptr;
#if !defined(__ANDROID__)
        test_installer = ::getenv("SKROOT_TEST_APK_INSTALLER");
#endif
        auto exec_installer = [&](const char* executable, const char* argv0) {
            std::vector<std::string> args = {
                argv0, "package", "install", "-r", "-d", "--user", "0", "-S", apk_size
            };
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (auto& arg : args) argv.push_back(arg.data());
            argv.push_back(nullptr);
            ::execv(executable, argv.data());
        };
        if (test_installer && *test_installer) exec_installer(test_installer, test_installer);
        if (::access("/system/bin/cmd", X_OK) == 0) exec_installer("/system/bin/cmd", "cmd");
        exec_installer("/system/bin/pm", "pm");
        _exit(127);
    }
    result.launched = true;
    ::close(input_pipe[0]);
    ::close(output_pipe[1]);
    (void)::setpgid(child, child);
    struct sigaction old_sigpipe {};
    struct sigaction ignore_sigpipe {};
    ignore_sigpipe.sa_handler = SIG_IGN;
    sigemptyset(&ignore_sigpipe.sa_mask);
    bool sigpipe_changed = ::sigaction(SIGPIPE, &ignore_sigpipe, &old_sigpipe) == 0;
    int flags = ::fcntl(input_pipe[1], F_GETFL, 0);
    if (flags >= 0) (void)::fcntl(input_pipe[1], F_SETFL, flags | O_NONBLOCK);
    flags = ::fcntl(output_pipe[0], F_GETFL, 0);
    if (flags >= 0) (void)::fcntl(output_pipe[0], F_SETFL, flags | O_NONBLOCK);

    std::array<char, 128 * 1024> input_buffer {};
    size_t input_offset = 0;
    size_t input_size = 0;
    bool input_eof = false;
    bool input_closed = false;
    bool input_error = false;
    bool exited = false;
    bool terminated = false;
    std::chrono::steady_clock::time_point terminated_at {};
    const auto started = std::chrono::steady_clock::now();
    const int timeout_seconds = apkInstallTimeoutSeconds();
    while (!exited) {
        pollfd descriptors[2] = {};
        nfds_t descriptor_count = 1;
        descriptors[0] = {output_pipe[0], POLLIN | POLLHUP, 0};
        if (!input_closed) {
            descriptors[1] = {input_pipe[1], POLLOUT | POLLERR | POLLHUP, 0};
            descriptor_count = 2;
        }
        (void)::poll(descriptors, descriptor_count, 100);

        std::array<char, 1024> output_buffer {};
        while (true) {
            const ssize_t value = ::read(output_pipe[0], output_buffer.data(), output_buffer.size());
            if (value > 0) {
                appendApkOutput(result.output, output_buffer.data(), static_cast<size_t>(value));
                continue;
            }
            if (value < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) break;
            break;
        }

        if (!input_closed && descriptor_count == 2
            && (descriptors[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            if (input_offset == input_size && !input_eof) {
                while (true) {
                    const ssize_t value = ::read(apk_input, input_buffer.data(), input_buffer.size());
                    if (value > 0) {
                        input_offset = 0;
                        input_size = static_cast<size_t>(value);
                        break;
                    }
                    if (value < 0 && errno == EINTR) continue;
                    if (value == 0) input_eof = true;
                    else input_error = true;
                    break;
                }
            }
            if (input_error) {
                result.output += "APK stream read failed: " + std::string(std::strerror(errno));
                input_eof = true;
            }
            if (input_offset < input_size) {
                const ssize_t value = ::write(input_pipe[1], input_buffer.data() + input_offset,
                                              input_size - input_offset);
                if (value > 0) input_offset += static_cast<size_t>(value);
                else if (value < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    input_eof = true;
                }
            }
            if (input_eof && input_offset == input_size) {
                ::close(input_pipe[1]);
                input_pipe[1] = -1;
                input_closed = true;
            }
        }

        const pid_t waited = ::waitpid(child, &result.status, WNOHANG);
        if (waited == child) exited = true;
        else if (waited < 0 && errno == ECHILD) {
            result.status = 1 << 8;
            exited = true;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started).count();
        if (!exited && !terminated && cancel.load(std::memory_order_acquire)) {
            (void)::kill(-child, SIGTERM);
            (void)::kill(child, SIGTERM);
            terminated = true;
            result.cancelled = true;
            terminated_at = std::chrono::steady_clock::now();
        }
        if (!exited && !terminated && elapsed >= timeout_seconds) {
            (void)::kill(-child, SIGTERM);
            (void)::kill(child, SIGTERM);
            terminated = true;
            result.timed_out = true;
            terminated_at = std::chrono::steady_clock::now();
        }
        if (!exited && terminated
            && std::chrono::steady_clock::now() - terminated_at >= std::chrono::seconds(1)) {
            (void)::kill(-child, SIGKILL);
            (void)::kill(child, SIGKILL);
        }
    }
    if (input_pipe[1] >= 0) ::close(input_pipe[1]);
    ::close(apk_input);
    while (true) {
        std::array<char, 1024> output_buffer {};
        const ssize_t value = ::read(output_pipe[0], output_buffer.data(), output_buffer.size());
        if (value <= 0) break;
        appendApkOutput(result.output, output_buffer.data(), static_cast<size_t>(value));
    }
    ::close(output_pipe[0]);
    if (sigpipe_changed) (void)::sigaction(SIGPIPE, &old_sigpipe, nullptr);
    if (cancel.load(std::memory_order_acquire)) result.cancelled = true;
    return true;
}

bool runApkInstall(const std::string& apk_path,
                   std::atomic<bool>& cancel,
                   const std::function<void(const JobSnapshot&)>& publish,
                   JobSnapshot& snapshot) {
    struct stat apk_stat {};
    const int apk_probe = ::open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (apk_probe < 0 || ::fstat(apk_probe, &apk_stat) != 0
        || !S_ISREG(apk_stat.st_mode) || apk_stat.st_size < 0) {
        const int value = errno == 0 ? EINVAL : errno;
        if (apk_probe >= 0) ::close(apk_probe);
        snapshot.result_code = "APK_INSTALL_FAILED";
        snapshot.failed_count++;
        snapshot.errors.push_back({"APK_INSTALL_FAILED", "APK input is no longer a regular file", value});
        publishJob(publish, snapshot);
        return false;
    }
    ::close(apk_probe);
    const uint64_t size = static_cast<uint64_t>(apk_stat.st_size);
    const std::string apk_size = std::to_string(size);
    snapshot.total_bytes = size;

    ApkInstallAttempt attempt;
    (void)runApkInstallAttempt(apk_path, apk_size, cancel, attempt);

    snapshot.current_path = apk_path;
    snapshot.processed_items = 1;
    snapshot.total_items = 1;
    snapshot.processed_bytes = size;
    snapshot.exit_code = WIFEXITED(attempt.status) ? WEXITSTATUS(attempt.status) : -1;
    snapshot.result_message = sanitizeApkOutput(attempt.output, apk_path);
    if (cancel.load(std::memory_order_acquire) || attempt.cancelled) {
        snapshot.result_code = "APK_INSTALL_CANCELLED";
        return false;
    }
    if (attempt.timed_out) {
        snapshot.result_code = "APK_INSTALL_TIMEOUT";
        snapshot.failed_count++;
        snapshot.errors.push_back({"APK_INSTALL_TIMEOUT", "APK installation timed out", ETIMEDOUT});
        publishJob(publish, snapshot);
        return false;
    }
    if (!WIFEXITED(attempt.status) || WEXITSTATUS(attempt.status) != 0) {
        snapshot.result_code = "APK_INSTALL_FAILED";
        snapshot.failed_count++;
        const int value = WIFEXITED(attempt.status) ? WEXITSTATUS(attempt.status) : EINTR;
        snapshot.errors.push_back({"APK_INSTALL_FAILED",
                                   snapshot.result_message.empty() ? "Package manager installation failed"
                                                                    : snapshot.result_message,
                                   value});
        publishJob(publish, snapshot);
        return false;
    }
    snapshot.result_code = "APK_INSTALL_COMPLETED";
    snapshot.success_count = 1;
    publishJob(publish, snapshot);
    return true;
}

} // namespace

bool operator==(const FileVersion& a, const FileVersion& b) {
    return a.device == b.device && a.inode == b.inode && a.size == b.size
        && a.mtime_sec == b.mtime_sec && a.mtime_nsec == b.mtime_nsec;
}

bool operator!=(const FileVersion& a, const FileVersion& b) {
    return !(a == b);
}

std::string randomHex(size_t byte_count) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::vector<uint8_t> bytes(byte_count, 0);
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t used = 0;
    if (fd >= 0) {
        while (used < bytes.size()) {
            ssize_t value = ::read(fd, bytes.data() + used, bytes.size() - used);
            if (value > 0) used += static_cast<size_t>(value);
            else if (value < 0 && errno == EINTR) continue;
            else break;
        }
        ::close(fd);
    }
    if (used != bytes.size()) {
        uint64_t seed = static_cast<uint64_t>(::getpid())
                      ^ static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&bytes));
        for (size_t i = used; i < bytes.size(); ++i) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            bytes[i] = static_cast<uint8_t>(seed & 0xff);
        }
    }
    std::string result;
    result.resize(byte_count * 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = kHex[bytes[i] >> 4];
        result[i * 2 + 1] = kHex[bytes[i] & 0x0f];
    }
    return result;
}

std::string operationTypeName(OperationType type) {
    switch (type) {
        case OperationType::Copy: return "copy";
        case OperationType::Move: return "move";
        case OperationType::Delete: return "delete";
        case OperationType::Extract: return "extract";
        case OperationType::Properties: return "properties";
        case OperationType::Compress: return "compress";
        case OperationType::InstallApk: return "install_apk";
    }
    return "unknown";
}

FileService::FileService(std::string special_comm) : m_special_comm(std::move(special_comm)) {}

void FileService::setSpecialComm(std::string special_comm) {
    m_special_comm = std::move(special_comm);
}

bool FileService::normalizeAbsolutePath(const std::string& input, std::string& output, Error& error) {
    if (input.empty() || input.front() != '/' || input.find('\0') != std::string::npos) {
        setError(error, "INVALID_PATH", "Path must be a non-empty absolute path");
        return false;
    }
    fs::path normalized = fs::path(input).lexically_normal();
    output = normalized.string();
    if (output.empty() || output.front() != '/') {
        setError(error, "INVALID_PATH", "Path normalization failed");
        return false;
    }
    while (output.size() > 1 && output.back() == '/') output.pop_back();
    return true;
}

bool FileService::isSameOrChildPath(const std::string& parent, const std::string& candidate) {
    if (parent == candidate) return true;
    if (parent == "/") return !candidate.empty() && candidate.front() == '/';
    return candidate.size() > parent.size()
        && candidate.compare(0, parent.size(), parent) == 0
        && candidate[parent.size()] == '/';
}

bool FileService::list(const std::string& path, std::string& out_items_json, Error& error) const {
    std::string normalized;
    if (!normalizeAbsolutePath(path, normalized, error)) return false;
    struct stat st {};
    if (::stat(normalized.c_str(), &st) != 0) {
        int value = errno;
        setError(error, "LIST_FAILED", errnoMessage("stat", normalized, value), value);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        setError(error, "NOT_DIRECTORY", "Path is not a directory: " + normalized, ENOTDIR);
        return false;
    }
    auto first = list_dir_helper::collect_dir_items(normalized);
    std::vector<list_dir_helper::FileItem> second;
    {
        list_dir_helper::ScopedProcComm guard;
        if (!m_special_comm.empty()) guard.set_temp(m_special_comm);
        second = list_dir_helper::collect_dir_items(normalized);
    }
    list_dir_helper::mark_hide_protected_items(first, second);
    out_items_json = list_dir_helper::build_list_dir_json(second);
    return true;
}

bool FileService::makeDirectory(const std::string& path, uint32_t mode, Error& error) const {
    std::string normalized;
    if (!normalizeAbsolutePath(path, normalized, error)) return false;
    if (::mkdir(normalized.c_str(), static_cast<mode_t>(mode & 0777)) != 0) {
        int value = errno;
        setError(error, value == EEXIST ? "TARGET_EXISTS" : "MKDIR_FAILED",
                 errnoMessage("mkdir", normalized, value), value);
        return false;
    }
    return true;
}

bool FileService::createFile(const std::string& path, uint32_t mode,
                             uint32_t& actual_mode, Error& error) const {
    std::string normalized;
    if (!normalizeAbsolutePath(path, normalized, error)) return false;
    if (normalized == "/") {
        setError(error, "ROOT_OPERATION_BLOCKED", "Creating the filesystem root is not allowed", EINVAL);
        return false;
    }
    int fd = ::open(normalized.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    static_cast<mode_t>(mode & 0777));
    if (fd < 0) {
        const int value = errno;
        setError(error, value == EEXIST ? "TARGET_EXISTS" : "CREATE_FAILED",
                 errnoMessage("create", normalized, value), value);
        return false;
    }
    struct stat st {};
    bool ok = ::fstat(fd, &st) == 0;
    int value = ok ? 0 : errno;
    if (ok && ::fsync(fd) != 0) {
        ok = false;
        value = errno;
    }
    ::close(fd);
    if (ok && !fsyncParent(normalized)) {
        value = errno;
        if (value != EINVAL && value != ENOTSUP && value != EOPNOTSUPP) ok = false;
    }
    if (!ok) {
        (void)::unlink(normalized.c_str());
        setError(error, "CREATE_FAILED", errnoMessage("fsync", normalized, value), value);
        return false;
    }
    actual_mode = static_cast<uint32_t>(st.st_mode & 07777);
    return true;
}

bool FileService::getProperties(const std::string& path, FileProperties& result, Error& error) const {
    std::string normalized;
    if (!normalizeAbsolutePath(path, normalized, error)) return false;
    struct stat st {};
    if (!lstatPath(normalized, st)) {
        const int value = errno;
        setError(error, "PROPERTIES_FAILED", errnoMessage("lstat", normalized, value), value);
        return false;
    }
    result = FileProperties{};
    result.path = normalized;
    result.name = normalized == "/" ? "/" : baseName(normalized);
    result.type = fileTypeFromMode(st.st_mode);
    result.size = static_cast<uint64_t>(std::max<off_t>(0, st.st_size));
    result.mtime_ms = mtimeMsFromStat(st);
    result.mode = static_cast<uint32_t>(st.st_mode & 07777);
    result.uid = static_cast<uint32_t>(st.st_uid);
    result.gid = static_cast<uint32_t>(st.st_gid);
    result.owner_name = userNameFor(result.uid);
    result.group_name = groupNameFor(result.gid);
    result.recursive_eligible = S_ISDIR(st.st_mode);
    if (S_ISLNK(st.st_mode)) {
        const size_t capacity = static_cast<size_t>(std::max<off_t>(PATH_MAX, st.st_size + 1)) + 1;
        std::vector<char> target(capacity, 0);
        ssize_t size = ::readlink(normalized.c_str(), target.data(), target.size() - 1);
        if (size >= 0) result.symlink_target.assign(target.data(), static_cast<size_t>(size));
    }
    return true;
}

bool FileService::listPrincipals(const std::string& path,
                                 std::vector<PrincipalEntry>& users,
                                 std::vector<PrincipalEntry>& groups,
                                 Error& error) const {
    FileProperties properties;
    if (!getProperties(path, properties, error)) return false;
    users = buildPrincipalList(true, properties.uid);
    groups = buildPrincipalList(false, properties.gid);
    return true;
}

bool FileService::resolveUser(const std::string& value, uint32_t& uid, Error& error) const {
    if (parseUnsignedId(value, uid)) return true;
    struct passwd entry {};
    struct passwd* found = nullptr;
    std::array<char, 4096> buffer {};
    if (::getpwnam_r(value.c_str(), &entry, buffer.data(), buffer.size(), &found) == 0 && found) {
        uid = static_cast<uint32_t>(found->pw_uid);
        return true;
    }
    auto candidates = buildPrincipalList(true, 0);
    auto it = std::find_if(candidates.begin(), candidates.end(), [&](const PrincipalEntry& item) {
        return item.name == value;
    });
    if (it != candidates.end()) {
        uid = it->id;
        return true;
    }
    setError(error, "INVALID_OWNER", "Unknown owner name or UID: " + value, EINVAL);
    return false;
}

bool FileService::resolveGroup(const std::string& value, uint32_t& gid, Error& error) const {
    if (parseUnsignedId(value, gid)) return true;
    {
        std::lock_guard<std::mutex> lock(groupLookupMutex());
        struct group* found = ::getgrnam(value.c_str());
        if (found) {
            gid = static_cast<uint32_t>(found->gr_gid);
            return true;
        }
    }
    auto candidates = buildPrincipalList(false, 0);
    auto it = std::find_if(candidates.begin(), candidates.end(), [&](const PrincipalEntry& item) {
        return item.name == value;
    });
    if (it != candidates.end()) {
        gid = it->id;
        return true;
    }
    setError(error, "INVALID_GROUP", "Unknown group name or GID: " + value, EINVAL);
    return false;
}

bool FileService::renamePath(const std::string& source, const std::string& target, Error& error) const {
    std::string normalized_source;
    std::string normalized_target;
    if (!normalizeAbsolutePath(source, normalized_source, error)
        || !normalizeAbsolutePath(target, normalized_target, error)) return false;
    if (normalized_source == "/" || normalized_target == "/") {
        setError(error, "ROOT_OPERATION_BLOCKED", "Renaming the filesystem root is not allowed", EINVAL);
        return false;
    }
    if (renameNoReplace(normalized_source, normalized_target) != 0) {
        int value = errno;
        setError(error, value == EEXIST || value == ENOTEMPTY ? "TARGET_EXISTS" : "RENAME_FAILED",
                 errnoMessage("renameat2", normalized_source, value), value);
        return false;
    }
    return true;
}

bool FileService::isDirectory(const std::string& path) const {
    std::string normalized;
    Error error;
    if (!normalizeAbsolutePath(path, normalized, error)) return false;
    struct stat st {};
    return ::stat(normalized.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

void FileService::runOperation(const OperationSpec& spec,
                               std::atomic<bool>& cancel_requested,
                               const std::function<void(const JobSnapshot&)>& publish,
                               JobSnapshot& snapshot) const {
    list_dir_helper::ScopedProcComm guard;
    if (!m_special_comm.empty()) guard.set_temp(m_special_comm);

    if (spec.type == OperationType::Properties) {
        PropertyRunner runner{spec, cancel_requested, publish, snapshot};
        snapshot.state = "scanning";
        publish(snapshot);
        const bool scanned = runner.scanTree(spec.sources.front(), true);
        if (cancel_requested.load(std::memory_order_acquire)) {
            snapshot.state = "cancelled";
        } else if (!scanned || snapshot.failed_count > 0) {
            snapshot.state = "failed";
        } else {
            snapshot.state = "running";
            publish(snapshot);
            const bool applied = runner.applyTree(spec.sources.front(), true);
            if (cancel_requested.load(std::memory_order_acquire)) snapshot.state = "cancelled";
            else if (!applied || snapshot.failed_count > 0) snapshot.state = "failed";
            else snapshot.state = "completed";
        }
        publish(snapshot);
        return;
    }

    if (spec.type == OperationType::Extract) {
        const ArchiveSelection* selection = spec.archive_selection.enabled ? &spec.archive_selection : nullptr;
        snapshot.state = "scanning";
        publish(snapshot);
        const bool scanned = ArchiveService::scan(spec.sources.front(), spec.destination,
                                                  cancel_requested, publish, snapshot, selection);
        if (cancel_requested.load(std::memory_order_acquire)) {
            snapshot.state = "cancelled";
        } else if (!scanned) {
            snapshot.state = "failed";
        } else {
            snapshot.state = "running";
            publish(snapshot);
            const bool extracted = ArchiveService::extract(spec.sources.front(), spec.destination,
                                                            spec.conflict, cancel_requested,
                                                            publish, snapshot, selection);
            if (cancel_requested.load(std::memory_order_acquire)) snapshot.state = "cancelled";
            else if (!extracted || snapshot.failed_count > 0) snapshot.state = "failed";
            else snapshot.state = "completed";
        }
        publish(snapshot);
        return;
    }

    if (spec.type == OperationType::Compress) {
        snapshot.state = "scanning";
        snapshot.output_path = spec.output_path;
        publish(snapshot);
        const bool compressed = ArchiveService::compress(spec.sources, spec.output_path,
                                                         cancel_requested, publish, snapshot);
        if (cancel_requested.load(std::memory_order_acquire)) snapshot.state = "cancelled";
        else if (!compressed || snapshot.failed_count > 0) snapshot.state = "failed";
        else snapshot.state = "completed";
        publish(snapshot);
        return;
    }

    if (spec.type == OperationType::InstallApk) {
        snapshot.state = "running";
        snapshot.total_items = 1;
        snapshot.current_path = spec.sources.front();
        publish(snapshot);
        const bool installed = runApkInstall(spec.sources.front(), cancel_requested, publish, snapshot);
        if (cancel_requested.load(std::memory_order_acquire)) snapshot.state = "cancelled";
        else if (!installed || snapshot.failed_count > 0) snapshot.state = "failed";
        else snapshot.state = "completed";
        publish(snapshot);
        return;
    }

    OperationRunner runner{spec, cancel_requested, publish, snapshot, {}};

    snapshot.state = "scanning";
    publish(snapshot);
    for (const auto& source : spec.sources) {
        if (!runner.scan(source) && runner.cancelled()) break;
    }
    if (runner.cancelled()) {
        snapshot.state = "cancelled";
        publish(snapshot);
        return;
    }

    snapshot.state = "running";
    publish(snapshot);
    for (const auto& source : spec.sources) {
        if (runner.cancelled()) break;
        snapshot.current_path = source;
        publish(snapshot);
        if (spec.type == OperationType::Delete) {
            runner.removeTree(source, true);
            continue;
        }
        std::string target = joinPath(spec.destination, baseName(source));
        if (spec.type == OperationType::Copy) runner.copyPath(source, target);
        else runner.movePath(source, target);
    }
    if (runner.cancelled()) {
        snapshot.state = "cancelled";
    } else if (snapshot.failed_count > 0 && snapshot.success_count == 0) {
        snapshot.state = "failed";
    } else {
        snapshot.state = "completed";
    }
    publish(snapshot);
}

FileJobManager::FileJobManager(FileService& service) : m_service(service) {}

FileJobManager::~FileJobManager() {
    shutdown();
}

void FileJobManager::joinFinishedThread() {
    if (!m_worker.joinable()) return;
    bool active = false;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        active = isActiveState(m_snapshot.state);
    }
    if (!active) m_worker.join();
}

bool FileJobManager::start(const OperationSpec& input, std::string& out_job_id, Error& error) {
    std::lock_guard<std::mutex> lifecycle_lk(m_lifecycle_mu);
    if (m_stop_requested.load(std::memory_order_acquire)) {
        setError(error, "FILE_SERVICE_STOPPED", "File service is stopping", ECANCELED); return false;
    }
    joinFinishedThread();
    {
        std::lock_guard<std::mutex> lk(m_mu);
        if (isActiveState(m_snapshot.state)) {
            setError(error, "JOB_BUSY", "Another file operation is still running", EBUSY);
            return false;
        }
    }
    if (input.sources.empty()) {
        setError(error, "INVALID_SOURCES", "The operation requires between 1 and 500 source paths");
        return false;
    }

    OperationSpec spec = input;
    if (spec.archive_selection.enabled && spec.type != OperationType::Extract) {
        setError(error, "INVALID_ARCHIVE_SELECTION", "Archive selection is only valid for extraction", EINVAL);
        return false;
    }
    std::set<std::string> unique_sources;
    for (const auto& source : input.sources) {
        std::string normalized;
        if (!FileService::normalizeAbsolutePath(source, normalized, error)) return false;
        if (normalized == "/") {
            setError(error, "ROOT_OPERATION_BLOCKED", "Operating on the filesystem root is not allowed");
            return false;
        }
        unique_sources.insert(normalized);
    }
    if (unique_sources.size() > kMaxOperationSources) {
        setError(error, "INVALID_SOURCES", "The operation accepts at most 500 unique source paths");
        return false;
    }
    spec.sources.assign(unique_sources.begin(), unique_sources.end());
    if (spec.type == OperationType::InstallApk) {
        if (spec.sources.size() != 1) {
            setError(error, "INVALID_SOURCES", "APK installation requires exactly one source file", EINVAL);
            return false;
        }
        const std::string name = baseName(spec.sources.front());
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        const bool has_apk_suffix = lower.size() >= 4
            && lower.compare(lower.size() - 4, 4, ".apk") == 0;
        const bool has_qq_wechat_suffix = lower.size() >= 6
            && lower.compare(lower.size() - 6, 6, ".apk.1") == 0;
        if (!has_apk_suffix && !has_qq_wechat_suffix) {
            setError(error, "INVALID_APK", "APK installation requires a .apk or .apk.1 file", EINVAL);
            return false;
        }
        struct stat apk_stat {};
        if (!lstatPath(spec.sources.front(), apk_stat) || !S_ISREG(apk_stat.st_mode)) {
            const int value = errno == 0 ? EINVAL : errno;
            setError(error, "INVALID_APK", "APK source must be a regular file", value);
            return false;
        }
    }
    if (spec.type == OperationType::Properties) {
        if (spec.sources.size() != 1) {
            setError(error, "INVALID_SOURCES", "Property changes require exactly one source path", EINVAL);
            return false;
        }
        if (!spec.properties.has_mode && !spec.properties.has_uid && !spec.properties.has_gid) {
            setError(error, "INVALID_PROPERTIES", "At least one property must be changed", EINVAL);
            return false;
        }
        if (spec.properties.has_mode && spec.properties.mode > 07777) {
            setError(error, "INVALID_MODE", "Mode must be between 0000 and 7777", EINVAL);
            return false;
        }
        struct stat property_stat {};
        if (!lstatPath(spec.sources.front(), property_stat)) {
            const int value = errno;
            setError(error, "PROPERTIES_FAILED", errnoMessage("lstat", spec.sources.front(), value), value);
            return false;
        }
    }
    if (spec.type == OperationType::Extract) {
        if (spec.sources.size() != 1) {
            setError(error, "INVALID_SOURCES", "Archive extraction requires exactly one source file");
            return false;
        }
        if (!ArchiveService::isSupportedSingleArchivePath(spec.sources.front())) {
            setError(error, "ARCHIVE_UNSUPPORTED_FORMAT",
                     "Only single-volume .zip, .rar and .7z files are supported", EINVAL);
            return false;
        }
        struct stat archive_stat {};
        if (!lstatPath(spec.sources.front(), archive_stat) || !S_ISREG(archive_stat.st_mode)) {
            const int value = errno == 0 ? EINVAL : errno;
            setError(error, "INVALID_ARCHIVE", "Archive source must be a regular file", value);
            return false;
        }
        if (spec.archive_selection.enabled) {
            auto& selection = spec.archive_selection;
            if (selection.archive_path != spec.sources.front() || selection.entries.empty()
                || selection.entries.size() > kMaxArchiveIndexEntries) {
                setError(error, "INVALID_ARCHIVE_SELECTION", "Archive selection does not match the source", EINVAL);
                return false;
            }
            if (versionFromStat(archive_stat) != selection.version) {
                setError(error, "ARCHIVE_CHANGED", "Archive changed; reopen it before extraction", ESTALE);
                return false;
            }
            std::sort(selection.entries.begin(), selection.entries.end(), [](const auto& a, const auto& b) {
                return a.header_index < b.header_index;
            });
            for (size_t i = 0; i < selection.entries.size(); ++i) {
                if (selection.entries[i].path.empty() || selection.entries[i].header_index >= kMaxArchiveIndexEntries
                    || (i > 0 && selection.entries[i - 1].header_index == selection.entries[i].header_index)) {
                    setError(error, "INVALID_ARCHIVE_SELECTION", "Archive selection contains invalid or duplicate entries", EINVAL);
                    return false;
                }
            }
        }
    }
    if (spec.type == OperationType::Compress) {
        if (spec.sources.empty()) {
            setError(error, "INVALID_SOURCES", "ZIP compression requires at least one source", EINVAL);
            return false;
        }
    }
    if (spec.type != OperationType::Delete && spec.type != OperationType::Properties
        && spec.type != OperationType::InstallApk) {
        if (!FileService::normalizeAbsolutePath(input.destination, spec.destination, error)) return false;
        if (!m_service.isDirectory(spec.destination)) {
            setError(error, "INVALID_DESTINATION", "Destination is not an accessible directory", ENOTDIR);
            return false;
        }
        if (spec.type != OperationType::Extract && spec.type != OperationType::Compress) {
            for (const auto& source : spec.sources) {
                std::string target = joinPath(spec.destination, baseName(source));
                if (FileService::isSameOrChildPath(source, target)
                    || destinationIsInsideDirectory(source, spec.destination)) {
                    setError(error, "INVALID_DESTINATION", "A directory cannot be copied or moved into itself");
                    return false;
                }
            }
        }
        if (spec.type == OperationType::Compress) {
            const std::string stem = zipArchiveStem(spec.sources);
            spec.output_path = joinPath(spec.destination, stem + ".zip");
            for (const auto& source : spec.sources) {
                if (destinationIsInsideDirectory(source, spec.destination)) {
                    setError(error, "INVALID_DESTINATION", "A ZIP output directory cannot be inside a source directory", EINVAL);
                    return false;
                }
            }
        }
    }

    m_cancel_requested.store(false, std::memory_order_release);
    if (m_stop_requested.load(std::memory_order_acquire)) {
        m_cancel_requested.store(true, std::memory_order_release);
        setError(error, "FILE_SERVICE_STOPPED", "File service is stopping", ECANCELED); return false;
    }
    JobSnapshot initial;
    initial.id = randomHex(12);
    initial.state = "scanning";
    initial.operation = operationTypeName(spec.type);
    initial.output_path = spec.output_path;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_snapshot = initial;
    }
    out_job_id = initial.id;
    m_worker = std::thread([this, spec, initial]() mutable {
        if (m_stop_requested.load(std::memory_order_acquire)) m_cancel_requested.store(true, std::memory_order_release);
        JobSnapshot local = initial;
        m_service.runOperation(spec, m_cancel_requested,
            [this](const JobSnapshot& value) { publish(value); }, local);
    });
    return true;
}

bool FileJobManager::cancel(const std::string& job_id, Error& error) {
    std::lock_guard<std::mutex> lk(m_mu);
    if (m_snapshot.id.empty() || (!job_id.empty() && job_id != m_snapshot.id)) {
        setError(error, "JOB_NOT_FOUND", "File operation job was not found", ENOENT);
        return false;
    }
    if (!isActiveState(m_snapshot.state)) return true;
    m_cancel_requested.store(true, std::memory_order_release);
    m_snapshot.state = "cancelling";
    return true;
}

JobSnapshot FileJobManager::snapshot(const std::string& job_id) const {
    std::lock_guard<std::mutex> lk(m_mu);
    if (!job_id.empty() && job_id != m_snapshot.id) {
        JobSnapshot missing;
        missing.id = job_id;
        missing.state = "not_found";
        return missing;
    }
    return m_snapshot;
}

bool FileJobManager::isActive() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return isActiveState(m_snapshot.state);
}

void FileJobManager::publish(const JobSnapshot& value) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_snapshot = value;
}

void FileJobManager::shutdown() {
    std::lock_guard<std::mutex> lifecycle_lk(m_lifecycle_mu);
    m_cancel_requested.store(true, std::memory_order_release);
    if (m_worker.joinable()) m_worker.join();
}

void FileJobManager::requestStop() {
    m_stop_requested.store(true, std::memory_order_release);
    m_cancel_requested.store(true, std::memory_order_release);
}

TextTransferService::TextTransferService() = default;

TextTransferService::~TextTransferService() {
    shutdown();
}

bool TextTransferService::getVersion(const std::string& path, FileVersion& version, Error& error) {
    struct stat st {};
    if (!lstatPath(path, st)) {
        int value = errno;
        setError(error, "STAT_FAILED", errnoMessage("lstat", path, value), value);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        setError(error, "NOT_REGULAR_FILE", "Path is not a regular file: " + path);
        return false;
    }
    version = versionFromStat(st);
    return true;
}

bool TextTransferService::isValidUtf8(const uint8_t* data, size_t size) {
    size_t i = 0;
    while (i < size) {
        uint8_t c = data[i++];
        if (c <= 0x7f) continue;
        uint32_t codepoint = 0;
        size_t continuation = 0;
        if ((c & 0xe0) == 0xc0) {
            codepoint = c & 0x1f;
            continuation = 1;
            if (codepoint < 2) return false;
        } else if ((c & 0xf0) == 0xe0) {
            codepoint = c & 0x0f;
            continuation = 2;
        } else if ((c & 0xf8) == 0xf0) {
            codepoint = c & 0x07;
            continuation = 3;
        } else {
            return false;
        }
        if (i + continuation > size) return false;
        for (size_t j = 0; j < continuation; ++j) {
            uint8_t next = data[i++];
            if ((next & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((continuation == 2 && codepoint < 0x800)
            || (continuation == 3 && codepoint < 0x10000)
            || codepoint > 0x10ffff
            || (codepoint >= 0xd800 && codepoint <= 0xdfff)) return false;
    }
    return true;
}

std::string TextTransferService::encodeBase64(const uint8_t* data, size_t size) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    for (size_t i = 0; i < size; i += 3) {
        uint32_t value = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < size) value |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < size) value |= data[i + 2];
        out.push_back(kAlphabet[(value >> 18) & 0x3f]);
        out.push_back(kAlphabet[(value >> 12) & 0x3f]);
        out.push_back(i + 1 < size ? kAlphabet[(value >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < size ? kAlphabet[value & 0x3f] : '=');
    }
    return out;
}

bool TextTransferService::decodeBase64(const std::string& text, std::vector<uint8_t>& out) {
    static std::array<int8_t, 256> table = [] {
        std::array<int8_t, 256> value {};
        value.fill(-1);
        const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (size_t i = 0; i < alphabet.size(); ++i) value[static_cast<uint8_t>(alphabet[i])] = static_cast<int8_t>(i);
        return value;
    }();
    if (text.size() % 4 != 0) return false;
    out.clear();
    out.reserve((text.size() / 4) * 3);
    for (size_t i = 0; i < text.size(); i += 4) {
        int a = table[static_cast<uint8_t>(text[i])];
        int b = table[static_cast<uint8_t>(text[i + 1])];
        int c = text[i + 2] == '=' ? -2 : table[static_cast<uint8_t>(text[i + 2])];
        int d = text[i + 3] == '=' ? -2 : table[static_cast<uint8_t>(text[i + 3])];
        const bool last_group = i + 4 == text.size();
        if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2)
            || (!last_group && (c == -2 || d == -2))) return false;
        uint32_t value = static_cast<uint32_t>(a << 18) | static_cast<uint32_t>(b << 12);
        if (c >= 0) value |= static_cast<uint32_t>(c << 6);
        if (d >= 0) value |= static_cast<uint32_t>(d);
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
        if (c >= 0) out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
        if (d >= 0) out.push_back(static_cast<uint8_t>(value & 0xff));
    }
    return true;
}

bool TextTransferService::openText(const std::string& input, TextOpenResult& result, Error& error) {
    std::string path;
    if (!FileService::normalizeAbsolutePath(input, path, error)) return false;
    TextFileReadInfo info;
    std::vector<uint8_t> bytes;
    if (!readAllFile(path, kMaxTextFileBytes, bytes, error, &info)) return false;
    if (!isValidUtf8(bytes.data(), bytes.size())) {
        setError(error, "INVALID_UTF8", "The selected file is not valid UTF-8 text");
        return false;
    }
    if (!info.read_only) {
        FileVersion current;
        if (!getVersion(path, current, error)) return false;
        if (current != info.version) {
            setError(error, "FILE_CHANGED", "The file changed while it was being opened", EBUSY);
            return false;
        }
    }

    std::lock_guard<std::mutex> lk(m_mu);
    if (m_reads.size() >= kMaxReadSessions) m_reads.erase(m_reads.begin());
    ReadSession session;
    do {
        session.id = randomHex(12);
    } while (m_reads.find(session.id) != m_reads.end());
    session.path = path;
    session.version = info.version;
    session.read_only = info.read_only;
    result.session_id = session.id;
    result.path = path;
    result.size = bytes.size();
    result.has_bom = bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf;
    result.read_only = info.read_only;
    result.version = info.version;
    // Kernel files can change on every read without changing stat metadata.
    // Serve the same bounded snapshot that was validated above to every chunk.
    if (info.read_only) session.snapshot = std::move(bytes);
    m_reads.emplace(session.id, std::move(session));
    return true;
}

bool TextTransferService::readChunk(const std::string& session_id,
                                    uint64_t offset,
                                    size_t limit,
                                    TextReadResult& result,
                                    Error& error) {
    std::lock_guard<std::mutex> lk(m_mu);
    auto session = m_reads.find(session_id);
    if (session_id.empty() || session == m_reads.end()) {
        setError(error, "TEXT_SESSION_NOT_FOUND", "Text read session was not found", ENOENT);
        return false;
    }
    if (session->second.read_only) {
        const auto& bytes = session->second.snapshot;
        if (offset > bytes.size()) {
            setError(error, "INVALID_OFFSET", "Read offset is beyond the end of the file", EINVAL);
            return false;
        }
        limit = std::min(limit == 0 ? kMaxTransferChunkBytes : limit, kMaxTransferChunkBytes);
        const size_t count = std::min<uint64_t>(limit, bytes.size() - offset);
        result.offset = offset;
        result.next_offset = offset + count;
        result.eof = result.next_offset == bytes.size();
        result.base64_data = encodeBase64(count ? bytes.data() + offset : nullptr, count);
        if (result.eof) m_reads.erase(session);
        return true;
    }
    FileVersion current;
    if (!getVersion(session->second.path, current, error)) return false;
    if (current != session->second.version) {
        setError(error, "FILE_CHANGED", "The file changed while it was being read", EBUSY);
        return false;
    }
    if (offset > current.size) {
        setError(error, "INVALID_OFFSET", "Read offset is beyond the end of the file", EINVAL);
        return false;
    }
    limit = std::min(limit == 0 ? kMaxTransferChunkBytes : limit, kMaxTransferChunkBytes);
    std::vector<uint8_t> bytes(std::min<uint64_t>(limit, current.size - offset), 0);
    int fd = ::open(session->second.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int value = errno;
        setError(error, "OPEN_FAILED", errnoMessage("open", session->second.path, value), value);
        return false;
    }
    struct stat opened_stat {};
    if (::fstat(fd, &opened_stat) != 0) {
        int value = errno;
        ::close(fd);
        setError(error, "STAT_FAILED", errnoMessage("fstat", session->second.path, value), value);
        return false;
    }
    if (versionFromStat(opened_stat) != session->second.version) {
        ::close(fd);
        setError(error, "FILE_CHANGED", "The file changed before the requested chunk was read", EBUSY);
        return false;
    }
    size_t used = 0;
    while (used < bytes.size()) {
        ssize_t value = ::pread(fd, bytes.data() + used, bytes.size() - used, static_cast<off_t>(offset + used));
        if (value > 0) used += static_cast<size_t>(value);
        else if (value == 0) break;
        else if (errno == EINTR) continue;
        else {
            int saved = errno;
            ::close(fd);
            setError(error, "READ_FAILED", errnoMessage("pread", session->second.path, saved), saved);
            return false;
        }
    }
    struct stat final_stat {};
    if (::fstat(fd, &final_stat) != 0) {
        int value = errno;
        ::close(fd);
        setError(error, "STAT_FAILED", errnoMessage("fstat", session->second.path, value), value);
        return false;
    }
    if (versionFromStat(final_stat) != session->second.version) {
        ::close(fd);
        setError(error, "FILE_CHANGED", "The file changed while the requested chunk was read", EBUSY);
        return false;
    }
    ::close(fd);
    bytes.resize(used);
    result.offset = offset;
    result.next_offset = offset + used;
    result.eof = result.next_offset >= current.size;
    result.base64_data = encodeBase64(bytes.data(), bytes.size());
    if (result.eof) m_reads.erase(session);
    return true;
}

bool TextTransferService::startSave(const std::string& input,
                                    const FileVersion& expected_version,
                                    uint64_t expected_size,
                                    bool force,
                                    std::string& out_save_id,
                                    Error& error) {
    if (expected_size > kMaxTextFileBytes) {
        setError(error, "TEXT_TOO_LARGE", "Text file exceeds the configured size limit");
        return false;
    }
    std::string path;
    if (!FileService::normalizeAbsolutePath(input, path, error)) return false;
    FileVersion current;
    if (!getVersion(path, current, error)) return false;
    if (!checkTextSaveFilesystem(path, error)) return false;
    if (!force && current != expected_version) {
        setError(error, "FILE_CHANGED", "The file changed after it was opened", EBUSY);
        return false;
    }

    std::lock_guard<std::mutex> lk(m_mu);
    if (!m_save.id.empty()) {
        setError(error, "SAVE_BUSY", "Another text save session is still active", EBUSY);
        return false;
    }
    m_save.id = randomHex(12);
    m_save.path = path;
    m_save.temp_path = joinPath(parentPath(path), ".skroot-edit-" + randomHex(8));
    m_save.expected_version = expected_version;
    m_save.expected_size = expected_size;
    m_save.force = force;
    m_save.fd = ::open(m_save.temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (m_save.fd < 0) {
        int value = errno;
        std::string temp = m_save.temp_path;
        clearSaveSession(m_save, false);
        setError(error, "SAVE_START_FAILED", errnoMessage("create", temp, value), value);
        return false;
    }
    out_save_id = m_save.id;
    return true;
}

bool TextTransferService::writeChunk(const std::string& save_id,
                                     uint64_t offset,
                                     const std::string& base64_data,
                                     uint64_t& out_received,
                                     Error& error) {
    std::vector<uint8_t> bytes;
    if (!decodeBase64(base64_data, bytes)) {
        setError(error, "INVALID_BASE64", "Text save chunk is not valid Base64");
        return false;
    }
    if (bytes.size() > kMaxTransferChunkBytes) {
        setError(error, "CHUNK_TOO_LARGE", "Text save chunk exceeds 128 KiB");
        return false;
    }

    std::lock_guard<std::mutex> lk(m_mu);
    if (save_id.empty() || save_id != m_save.id || m_save.fd < 0) {
        setError(error, "SAVE_SESSION_NOT_FOUND", "Text save session was not found", ENOENT);
        return false;
    }
    if (offset != m_save.received || m_save.received + bytes.size() > m_save.expected_size) {
        setError(error, "INVALID_OFFSET", "Text chunks must be written sequentially", EINVAL);
        return false;
    }
    if (!writeAll(m_save.fd, bytes.data(), bytes.size())) {
        int value = errno;
        setError(error, "WRITE_FAILED", errnoMessage("write", m_save.temp_path, value), value);
        return false;
    }
    m_save.received += bytes.size();
    out_received = m_save.received;
    return true;
}

bool TextTransferService::commitSave(const std::string& save_id,
                                     bool force,
                                     FileVersion& out_version,
                                     Error& error) {
    std::lock_guard<std::mutex> lk(m_mu);
    if (save_id.empty() || save_id != m_save.id || m_save.fd < 0) {
        setError(error, "SAVE_SESSION_NOT_FOUND", "Text save session was not found", ENOENT);
        return false;
    }
    if (m_save.received != m_save.expected_size) {
        setError(error, "INCOMPLETE_SAVE", "Not all text chunks have been received", EINVAL);
        return false;
    }
    FileVersion current;
    if (!getVersion(m_save.path, current, error)) return false;
    if (!checkTextSaveFilesystem(m_save.path, error)) return false;
    if (!(force || m_save.force) && current != m_save.expected_version) {
        setError(error, "FILE_CHANGED", "The file changed after it was opened", EBUSY);
        return false;
    }
    if (::fsync(m_save.fd) != 0) {
        int value = errno;
        setError(error, "SYNC_FAILED", errnoMessage("fsync", m_save.temp_path, value), value);
        return false;
    }
    std::vector<uint8_t> bytes;
    if (!readAllFile(m_save.temp_path, kMaxTextFileBytes, bytes, error)) return false;
    if (!isValidUtf8(bytes.data(), bytes.size())) {
        setError(error, "INVALID_UTF8", "Saved content is not valid UTF-8");
        return false;
    }

    struct stat original {};
    if (!lstatPath(m_save.path, original)) {
        int value = errno;
        setError(error, "STAT_FAILED", errnoMessage("lstat", m_save.path, value), value);
        return false;
    }
    if (!(force || m_save.force) && versionFromStat(original) != m_save.expected_version) {
        setError(error, "FILE_CHANGED", "The file changed before the save was committed", EBUSY);
        return false;
    }
    bestEffortApplyMetadata(m_save.path, m_save.temp_path, original, false);
    FileVersion before_rename;
    if (!getVersion(m_save.path, before_rename, error)) return false;
    if (!(force || m_save.force) && before_rename != m_save.expected_version) {
        setError(error, "FILE_CHANGED", "The file changed before the save was committed", EBUSY);
        return false;
    }
    if (::fsync(m_save.fd) != 0) {
        int value = errno;
        setError(error, "SYNC_FAILED", errnoMessage("fsync", m_save.temp_path, value), value);
        return false;
    }
    ::close(m_save.fd);
    m_save.fd = -1;
    if (::rename(m_save.temp_path.c_str(), m_save.path.c_str()) != 0) {
        int value = errno;
        setError(error, "COMMIT_FAILED", errnoMessage("rename", m_save.path, value), value);
        return false;
    }
    (void)fsyncParent(m_save.path);
    std::string path = m_save.path;
    clearSaveSession(m_save, false);
    return getVersion(path, out_version, error);
}

bool TextTransferService::abortSave(const std::string& save_id, Error& error) {
    std::lock_guard<std::mutex> lk(m_mu);
    if (m_save.id.empty()) return true;
    if (!save_id.empty() && save_id != m_save.id) {
        setError(error, "SAVE_SESSION_NOT_FOUND", "Text save session was not found", ENOENT);
        return false;
    }
    clearSaveSession(m_save, true);
    return true;
}

bool TextTransferService::hasActiveSave() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return !m_save.id.empty();
}

void TextTransferService::clearSaveSession(SaveSession& session, bool remove_temp) {
    if (session.fd >= 0) ::close(session.fd);
    if (remove_temp && !session.temp_path.empty()) (void)::unlink(session.temp_path.c_str());
    session = SaveSession{};
}

void TextTransferService::shutdown() {
    std::lock_guard<std::mutex> lk(m_mu);
    clearSaveSession(m_save, true);
    m_reads.clear();
}

} // namespace file_manager
