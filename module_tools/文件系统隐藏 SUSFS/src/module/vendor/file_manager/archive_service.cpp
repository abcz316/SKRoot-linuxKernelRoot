#include "archive_service.h"

#include "third_party/libarchive/include/archive.h"
#include "third_party/libarchive/include/archive_entry.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <locale.h>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <zlib.h>

namespace fs = std::filesystem;

namespace file_manager {
namespace {

constexpr size_t kArchiveReadBlockBytes = 128 * 1024;
constexpr uint64_t kMaxArchiveEntries = kMaxArchiveIndexEntries;
constexpr size_t kMaxRecordedArchiveMessages = 50;

// libarchive exposes UTF-8 path accessors, but its ZIP reader still performs
// pathname conversion while advancing to a header. A native Android process
// commonly starts with the plain C locale; in that locale a valid UTF-8 entry
// can be returned as ARCHIVE_WARN with a null pathname. Keep the adjustment
// thread-local so the rest of the WebUI is unaffected, and restore the caller's
// locale as soon as the archive operation finishes.
class ScopedUtf8Locale {
public:
    ScopedUtf8Locale() {
        static constexpr const char* kCandidates[] = {
            "C.UTF-8", "C.utf8", "UTF-8", "en_US.UTF-8"
        };
        for (const char* candidate : kCandidates) {
            m_locale = ::newlocale(LC_CTYPE_MASK, candidate, nullptr);
            if (m_locale) {
                m_previous = ::uselocale(m_locale);
                m_active = true;
                break;
            }
        }
    }

    ~ScopedUtf8Locale() {
        if (!m_active) return;
        (void)::uselocale(m_previous);
        ::freelocale(m_locale);
    }

    ScopedUtf8Locale(const ScopedUtf8Locale&) = delete;
    ScopedUtf8Locale& operator=(const ScopedUtf8Locale&) = delete;

private:
    locale_t m_locale = nullptr;
    locale_t m_previous = nullptr;
    bool m_active = false;
};

struct ArchiveDeleter {
    void operator()(archive* value) const {
        if (value) archive_read_free(value);
    }
};
using ArchivePtr = std::unique_ptr<archive, ArchiveDeleter>;

struct ArchiveWriterDeleter {
    void operator()(archive* value) const {
        if (value) archive_write_free(value);
    }
};
using ArchiveWriterPtr = std::unique_ptr<archive, ArchiveWriterDeleter>;

class ScopedFd {
public:
    ScopedFd() = default;
    explicit ScopedFd(int fd) : m_fd(fd) {}
    ~ScopedFd() { reset(); }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept : m_fd(other.release()) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }

    int get() const { return m_fd; }
    explicit operator bool() const { return m_fd >= 0; }
    int release() {
        int value = m_fd;
        m_fd = -1;
        return value;
    }
    void reset(int fd = -1) {
        if (m_fd >= 0) ::close(m_fd);
        m_fd = fd;
    }

private:
    int m_fd = -1;
};

DIR* openDirectoryNoFollow(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nullptr;
    DIR* result = ::fdopendir(fd);
    if (!result) {
        const int value = errno;
        ::close(fd);
        errno = value;
    }
    return result;
}

struct EntryPath {
    std::string relative;
    std::vector<std::string> parts;
};

struct XattrValue {
    std::string name;
    std::vector<uint8_t> value;
};

struct EntryMetadata {
    std::vector<std::string> parts;
    mode_t mode = 0755;
    int64_t uid = -1;
    int64_t gid = -1;
    bool has_mtime = false;
    timespec mtime {};
    std::vector<XattrValue> xattrs;
};

enum class PrepareResult {
    Ready,
    Skip,
    Failed,
};

void emit(const ArchiveService::Publisher& publish, const JobSnapshot& snapshot) {
    publish(snapshot);
}

void recordError(JobSnapshot& snapshot,
                 const ArchiveService::Publisher& publish,
                 std::string code,
                 std::string message,
                 int value = 0) {
    snapshot.failed_count++;
    if (snapshot.errors.size() < kMaxRecordedArchiveMessages) {
        snapshot.errors.push_back({std::move(code), std::move(message), value});
    }
    emit(publish, snapshot);
}

void recordWarning(JobSnapshot& snapshot,
                   const ArchiveService::Publisher& publish,
                   std::string code,
                   std::string message,
                   int value = 0) {
    snapshot.warning_count++;
    if (snapshot.warnings.size() < kMaxRecordedArchiveMessages) {
        snapshot.warnings.push_back({std::move(code), std::move(message), value});
    }
    emit(publish, snapshot);
}

std::string archiveMessage(archive* reader, const std::string& action) {
    const char* detail = archive_error_string(reader);
    return action + (detail && *detail ? ": " + std::string(detail) : "");
}

bool containsIgnoreCase(std::string value, const std::string& needle) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value.find(needle) != std::string::npos;
}

std::string archiveErrorCode(archive* reader) {
    const char* detail = archive_error_string(reader);
    const std::string message = detail ? detail : "";
    if (containsIgnoreCase(message, "passphrase") || containsIgnoreCase(message, "encrypted")) {
        return "ARCHIVE_ENCRYPTED";
    }
    return "ARCHIVE_READ_FAILED";
}

bool matchesVersion(const struct stat& value, const FileVersion& expected) {
#if defined(__APPLE__)
    const timespec modified = value.st_mtimespec;
#else
    const timespec modified = value.st_mtim;
#endif
    return S_ISREG(value.st_mode)
        && static_cast<uint64_t>(value.st_dev) == expected.device
        && static_cast<uint64_t>(value.st_ino) == expected.inode
        && static_cast<uint64_t>(std::max<off_t>(0, value.st_size)) == expected.size
        && modified.tv_sec == expected.mtime_sec && modified.tv_nsec == expected.mtime_nsec;
}

bool versionUnchanged(const std::string& path, const FileVersion& expected) {
    struct stat value {};
    return ::lstat(path.c_str(), &value) == 0 && matchesVersion(value, expected);
}

ArchivePtr openArchive(const std::string& path, JobSnapshot& snapshot,
                       const ArchiveService::Publisher& publish,
                       ScopedFd* source = nullptr, const FileVersion* expected = nullptr) {
    ArchivePtr reader(archive_read_new());
    if (!reader) {
        recordError(snapshot, publish, "ARCHIVE_INIT_FAILED", "Failed to allocate archive reader", ENOMEM);
        return {};
    }
    archive_read_support_filter_none(reader.get());
    archive_read_support_format_zip(reader.get());
    archive_read_support_format_7zip(reader.get());
    archive_read_support_format_rar(reader.get());
    archive_read_support_format_rar5(reader.get());
    int opened = ARCHIVE_FATAL;
    if (source && expected) {
        source->reset(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
        struct stat current {};
        if (!*source || ::fstat(source->get(), &current) != 0 || !matchesVersion(current, *expected)) {
            recordError(snapshot, publish, "ARCHIVE_CHANGED", "Archive changed; reopen it before continuing", ESTALE);
            return {};
        }
        opened = archive_read_open_fd(reader.get(), source->get(), kArchiveReadBlockBytes);
    } else {
        opened = archive_read_open_filename(reader.get(), path.c_str(), kArchiveReadBlockBytes);
    }
    if (opened != ARCHIVE_OK) {
        recordError(snapshot, publish, archiveErrorCode(reader.get()),
                    archiveMessage(reader.get(), "Failed to open archive"), archive_errno(reader.get()));
        return {};
    }
    return reader;
}

bool isAllowedFormat(archive* reader) {
    const int base = archive_format(reader) & ARCHIVE_FORMAT_BASE_MASK;
    return base == ARCHIVE_FORMAT_ZIP || base == ARCHIVE_FORMAT_7ZIP
        || base == ARCHIVE_FORMAT_RAR || base == ARCHIVE_FORMAT_RAR_V5;
}

bool isDigits(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

std::string lowerName(const std::string& path);

bool hasCompanionVolume(const std::string& path) {
    std::error_code ec;
    const fs::path archive_path(path);
    const fs::path parent = archive_path.parent_path().empty() ? fs::path(".") : archive_path.parent_path();
    const std::string name = lowerName(path);
    std::string prefix;
    enum class CompanionKind { Zip, Rar, SevenZip, None } kind = CompanionKind::None;
    if (name.size() >= 4 && name.compare(name.size() - 4, 4, ".zip") == 0) {
        prefix = name.substr(0, name.size() - 4);
        kind = CompanionKind::Zip;
    } else if (name.size() >= 4 && name.compare(name.size() - 4, 4, ".rar") == 0) {
        prefix = name.substr(0, name.size() - 4);
        kind = CompanionKind::Rar;
    } else if (name.size() >= 3 && name.compare(name.size() - 3, 3, ".7z") == 0) {
        prefix = name;
        kind = CompanionKind::SevenZip;
    }
    if (kind == CompanionKind::None) return false;

    for (fs::directory_iterator it(parent, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string candidate = lowerName(it->path().string());
        bool companion = false;
        if (kind == CompanionKind::Zip) {
            // Split ZIPs conventionally use .z01/.z02 or .zip.001 companions.
            const std::string zprefix = prefix + ".z";
            const std::string numbered_prefix = prefix + ".zip.";
            if (candidate.rfind(zprefix, 0) == 0 && isDigits(std::string_view(candidate).substr(zprefix.size()))) {
                companion = true;
            } else if (candidate.rfind(numbered_prefix, 0) == 0
                       && isDigits(std::string_view(candidate).substr(numbered_prefix.size()))) {
                companion = true;
            }
        } else if (kind == CompanionKind::Rar) {
            // Legacy RAR volumes use archive.r00, archive.r01, ... next to archive.rar.
            const std::string rprefix = prefix + ".r";
            const std::string suffix = candidate.rfind(rprefix, 0) == 0
                ? candidate.substr(rprefix.size()) : std::string{};
            companion = suffix.size() == 2 && isDigits(suffix);
        } else {
            const std::string seven_prefix = prefix + ".";
            const std::string suffix = candidate.rfind(seven_prefix, 0) == 0
                ? candidate.substr(seven_prefix.size()) : std::string{};
            companion = suffix.size() == 3 && isDigits(suffix);
        }
        if (companion) {
            struct stat st {};
            if (::lstat(it->path().c_str(), &st) == 0) return true;
        }
    }
    return false;
}

std::string lowerName(const std::string& path) {
    std::string value = fs::path(path).filename().string();
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool normalizeEntryPath(const char* raw, EntryPath& result, std::string& reason) {
    result = EntryPath{};
    if (!raw || !*raw) {
        reason = "Archive entry has an empty pathname";
        return false;
    }
    const size_t raw_size = std::strlen(raw);
    if (!TextTransferService::isValidUtf8(reinterpret_cast<const uint8_t*>(raw), raw_size)) {
        reason = "Archive entry pathname is not valid UTF-8";
        return false;
    }

    std::string path(raw, raw_size);
    std::replace(path.begin(), path.end(), '\\', '/');
    if (path.empty() || path.front() == '/' || path.find('\0') != std::string::npos
        || (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':')) {
        reason = "Archive entry uses an absolute pathname: " + path;
        return false;
    }

    size_t start = 0;
    while (start <= path.size()) {
        const size_t slash = path.find('/', start);
        const size_t end = slash == std::string::npos ? path.size() : slash;
        std::string part = path.substr(start, end - start);
        if (!part.empty() && part != ".") {
            if (part == "..") {
                reason = "Archive entry attempts parent traversal: " + path;
                return false;
            }
            if (part.size() > NAME_MAX) {
                reason = "Archive entry component is too long: " + path;
                return false;
            }
            result.parts.push_back(std::move(part));
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }

    if (result.parts.empty()) {
        result.relative.clear();
        return true;
    }
    for (const auto& part : result.parts) {
        if (!result.relative.empty()) result.relative.push_back('/');
        result.relative += part;
    }
    if (result.relative.size() >= PATH_MAX) {
        reason = "Archive entry pathname is too long";
        return false;
    }
    return true;
}

// Selection paths are already normalized by the browser. Recheck ordinals and
// paths on every pass so a stale index cannot select a different same-name file.
bool mapSelectedPath(const ArchiveSelection* selection, uint64_t header_index,
                     EntryPath& path, bool& selected, std::string& reason) {
    selected = true;
    if (!selection || !selection->enabled) return true;
    const auto found = std::lower_bound(selection->entries.begin(), selection->entries.end(), header_index,
        [](const ArchiveSelectedEntry& entry, uint64_t index) { return entry.header_index < index; });
    if (found == selection->entries.end() || found->header_index != header_index) {
        selected = false;
        return true;
    }
    if (found->path != path.relative) {
        reason = "Archive entry no longer matches the selected item";
        return false;
    }
    if (selection->base_path.empty()) return true;
    const std::string prefix = selection->base_path + "/";
    if (path.relative.compare(0, prefix.size(), prefix) != 0) {
        reason = "Selected archive entry is outside the current archive directory";
        return false;
    }
    const std::string relative = path.relative.substr(prefix.size());
    return normalizeEntryPath(relative.c_str(), path, reason) && !path.parts.empty();
}

mode_t entryType(archive_entry* entry, const std::string& raw_path) {
    const mode_t type = archive_entry_filetype(entry);
    if (type) return type;
    return !raw_path.empty() && (raw_path.back() == '/' || raw_path.back() == '\\') ? AE_IFDIR : AE_IFREG;
}

const char* entryPathname(archive_entry* entry) {
    const char* value = archive_entry_pathname_utf8(entry);
    return value ? value : archive_entry_pathname(entry);
}

uint16_t zipLe16(const uint8_t* value) {
    return static_cast<uint16_t>(value[0])
        | static_cast<uint16_t>(static_cast<uint16_t>(value[1]) << 8);
}

uint32_t zipLe32(const uint8_t* value) {
    return static_cast<uint32_t>(value[0])
        | (static_cast<uint32_t>(value[1]) << 8)
        | (static_cast<uint32_t>(value[2]) << 16)
        | (static_cast<uint32_t>(value[3]) << 24);
}

bool preadAll(int fd, void* output, size_t size, off_t offset) {
    auto* bytes = static_cast<uint8_t*>(output);
    size_t used = 0;
    while (used < size) {
        const ssize_t value = ::pread(fd, bytes + used, size - used,
                                      offset + static_cast<off_t>(used));
        if (value > 0) used += static_cast<size_t>(value);
        else if (value < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

std::string unicodeZipExtraPath(const std::vector<uint8_t>& extra,
                                const std::vector<uint8_t>& raw_name) {
    size_t offset = 0;
    while (offset + 4 <= extra.size()) {
        const uint16_t id = zipLe16(extra.data() + offset);
        const uint16_t size = zipLe16(extra.data() + offset + 2);
        offset += 4;
        if (size > extra.size() - offset) break;
        if (id == 0x7075 && size >= 5 && extra[offset] == 1) {
            const uint32_t expected_crc = zipLe32(extra.data() + offset + 1);
            const uint32_t actual_crc = static_cast<uint32_t>(
                ::crc32(0, raw_name.data(), static_cast<uInt>(raw_name.size())));
            const uint8_t* path = extra.data() + offset + 5;
            const size_t path_size = size - 5;
            if (actual_crc == expected_crc && path_size > 0
                && TextTransferService::isValidUtf8(path, path_size)) {
                return std::string(reinterpret_cast<const char*>(path), path_size);
            }
        }
        offset += size;
    }
    return {};
}

// Android's native C.UTF-8 locale accepts UTF-8 input, but libarchive's
// charset bridge can still return ARCHIVE_WARN with a null pathname for ZIPs
// produced by a number of Windows tools.  Read only the central-directory
// names as a fallback; libarchive remains responsible for all payload parsing,
// encryption checks and CRC validation.
std::vector<std::string> readZipUtf8PathFallbacks(const std::string& archive_path,
                                               size_t byte_limit,
                                               bool& too_large,
                                               const std::atomic<bool>* cancel) {
    ScopedFd input(::open(archive_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!input) return {};
    struct stat st {};
    if (::fstat(input.get(), &st) != 0 || st.st_size < 22) return {};

    const uint64_t file_size = static_cast<uint64_t>(st.st_size);
    const size_t tail_size = static_cast<size_t>(std::min<uint64_t>(file_size, 65557));
    std::vector<uint8_t> tail(tail_size);
    const off_t tail_offset = static_cast<off_t>(file_size - tail_size);
    if (!preadAll(input.get(), tail.data(), tail.size(), tail_offset)) return {};

    size_t eocd = std::string::npos;
    for (size_t candidate = tail.size() - 22;; --candidate) {
        if (zipLe32(tail.data() + candidate) == 0x06054b50
            && candidate + 22 + zipLe16(tail.data() + candidate + 20) == tail.size()) {
            eocd = candidate;
            break;
        }
        if (candidate == 0) break;
    }
    if (eocd == std::string::npos) return {};
    const uint16_t disk = zipLe16(tail.data() + eocd + 4);
    const uint16_t central_disk = zipLe16(tail.data() + eocd + 6);
    const uint16_t disk_entries = zipLe16(tail.data() + eocd + 8);
    const uint16_t total_entries = zipLe16(tail.data() + eocd + 10);
    const uint32_t central_size = zipLe32(tail.data() + eocd + 12);
    const uint32_t central_offset_field = zipLe32(tail.data() + eocd + 16);
    if (disk != 0 || central_disk != 0 || disk_entries != total_entries
        || total_entries == 0xffff || central_size == 0xffffffffU
        || central_offset_field == 0xffffffffU) return {};

    const uint64_t eocd_file_offset = static_cast<uint64_t>(tail_offset) + eocd;
    if (central_size > eocd_file_offset) return {};
    const uint64_t central_offset = eocd_file_offset - central_size;
    uint64_t cursor = central_offset;
    struct NamedEntry { uint32_t local_offset; std::string path; };
    std::vector<NamedEntry> entries;
    entries.reserve(total_entries);
    size_t pathname_bytes = 0;
    for (uint32_t index = 0; index < total_entries; ++index) {
        if (cancel && cancel->load(std::memory_order_acquire)) return {};
        std::array<uint8_t, 46> header {};
        if (cursor > file_size || !preadAll(input.get(), header.data(), header.size(),
                                             static_cast<off_t>(cursor))
            || zipLe32(header.data()) != 0x02014b50) return {};
        const uint16_t flags = zipLe16(header.data() + 8);
        const uint16_t name_size = zipLe16(header.data() + 28);
        const uint16_t extra_size = zipLe16(header.data() + 30);
        const uint16_t comment_size = zipLe16(header.data() + 32);
        const uint64_t record_size = 46ULL + name_size + extra_size + comment_size;
        if (record_size > file_size - cursor) return {};
        std::vector<uint8_t> raw_name(name_size);
        std::vector<uint8_t> extra(extra_size);
        if ((name_size > 0 && !preadAll(input.get(), raw_name.data(), raw_name.size(),
                                        static_cast<off_t>(cursor + 46)))
            || (extra_size > 0 && !preadAll(input.get(), extra.data(), extra.size(),
                                            static_cast<off_t>(cursor + 46 + name_size)))) return {};
        std::string path;
        if ((flags & 0x0800) != 0 && !raw_name.empty()
            && TextTransferService::isValidUtf8(raw_name.data(), raw_name.size())) {
            path.assign(reinterpret_cast<const char*>(raw_name.data()), raw_name.size());
        } else {
            path = unicodeZipExtraPath(extra, raw_name);
            if (path.empty() && !raw_name.empty()
                && TextTransferService::isValidUtf8(raw_name.data(), raw_name.size())) {
                path.assign(reinterpret_cast<const char*>(raw_name.data()), raw_name.size());
            }
        }
        if (path.size() > byte_limit - pathname_bytes) {
            too_large = true;
            return {};
        }
        pathname_bytes += path.size();
        entries.push_back({zipLe32(header.data() + 42), std::move(path)});
        cursor += record_size;
    }
    std::stable_sort(entries.begin(), entries.end(), [](const NamedEntry& left, const NamedEntry& right) {
        return left.local_offset < right.local_offset;
    });
    std::vector<std::string> paths;
    paths.reserve(entries.size());
    for (auto& entry : entries) paths.push_back(std::move(entry.path));
    return paths;
}

class ArchivePathResolver {
public:
    explicit ArchivePathResolver(const std::string& archive_path,
                                 size_t byte_limit = std::numeric_limits<size_t>::max(),
                                 const std::atomic<bool>* cancel = nullptr) {
        m_zip_paths = readZipUtf8PathFallbacks(archive_path, byte_limit, m_too_large, cancel);
#if !defined(__ANDROID__)
        const char* force = ::getenv("SKROOT_TEST_FORCE_ARCHIVE_PATH_FALLBACK");
        m_force_fallback = force && std::strcmp(force, "1") == 0;
#endif
    }

    bool tooLarge() const { return m_too_large; }

    std::string next(archive_entry* entry) {
        const char* direct = entryPathname(entry);
        const size_t index = m_index++;
        if (!m_force_fallback && direct && *direct) return direct;
        return index < m_zip_paths.size() ? m_zip_paths[index] : std::string{};
    }

private:
    std::vector<std::string> m_zip_paths;
    size_t m_index = 0;
    bool m_force_fallback = false;
    bool m_too_large = false;
};

const char* entrySymlink(archive_entry* entry) {
    const char* value = archive_entry_symlink_utf8(entry);
    return value ? value : archive_entry_symlink(entry);
}

bool validContainedSymlink(const std::vector<std::string>& parent_parts, const char* raw) {
    if (!raw || !*raw) return false;
    const size_t size = std::strlen(raw);
    if (!TextTransferService::isValidUtf8(reinterpret_cast<const uint8_t*>(raw), size)) return false;
    std::string value(raw, size);
    std::replace(value.begin(), value.end(), '\\', '/');
    if (value.front() == '/' || (value.size() >= 2
        && std::isalpha(static_cast<unsigned char>(value[0])) && value[1] == ':')) return false;

    std::vector<std::string> resolved = parent_parts;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t slash = value.find('/', start);
        const size_t end = slash == std::string::npos ? value.size() : slash;
        const std::string part = value.substr(start, end - start);
        if (part == "..") {
            if (resolved.empty()) return false;
            resolved.pop_back();
        } else if (!part.empty() && part != ".") {
            resolved.push_back(part);
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

bool removeAtTree(int parent_fd, const std::string& name, std::atomic<bool>& cancel) {
    if (cancel.load(std::memory_order_acquire)) {
        errno = ECANCELED;
        return false;
    }
    struct stat st {};
    if (::fstatat(parent_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(st.st_mode)) return ::unlinkat(parent_fd, name.c_str(), 0) == 0;

    ScopedFd child(::openat(parent_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!child) return false;
    const int child_fd = child.release();
    DIR* dir = ::fdopendir(child_fd);
    if (!dir) {
        const int value = errno;
        ::close(child_fd);
        errno = value;
        return false;
    }
    bool ok = true;
    while (!cancel.load(std::memory_order_acquire)) {
        errno = 0;
        dirent* item = ::readdir(dir);
        if (!item) {
            if (errno != 0) ok = false;
            break;
        }
        if (std::strcmp(item->d_name, ".") == 0 || std::strcmp(item->d_name, "..") == 0) continue;
        if (!removeAtTree(::dirfd(dir), item->d_name, cancel)) {
            ok = false;
            break;
        }
    }
    ::closedir(dir);
    if (!ok || cancel.load(std::memory_order_acquire)) {
        if (cancel.load(std::memory_order_acquire)) errno = ECANCELED;
        return false;
    }
    return ::unlinkat(parent_fd, name.c_str(), AT_REMOVEDIR) == 0;
}

ScopedFd openParentDirectory(int root_fd,
                             const EntryPath& path,
                             ConflictPolicy conflict,
                             std::atomic<bool>& cancel,
                             bool& skipped,
                             std::string& failed_component) {
    skipped = false;
    ScopedFd current(::dup(root_fd));
    if (!current) return {};
    for (size_t i = 0; i + 1 < path.parts.size(); ++i) {
        if (cancel.load(std::memory_order_acquire)) {
            errno = ECANCELED;
            return {};
        }
        const std::string& part = path.parts[i];
        struct stat st {};
        if (::fstatat(current.get(), part.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT || ::mkdirat(current.get(), part.c_str(), 0755) != 0) {
                failed_component = part;
                return {};
            }
        } else if (!S_ISDIR(st.st_mode)) {
            if (conflict == ConflictPolicy::Skip) {
                skipped = true;
                return {};
            }
            if (!removeAtTree(current.get(), part, cancel)
                || ::mkdirat(current.get(), part.c_str(), 0755) != 0) {
                failed_component = part;
                return {};
            }
        }
        ScopedFd next(::openat(current.get(), part.c_str(),
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (!next) {
            failed_component = part;
            return {};
        }
        current = std::move(next);
    }
    return current;
}

PrepareResult prepareLeaf(int parent_fd,
                          const std::string& name,
                          bool wants_directory,
                          ConflictPolicy conflict,
                          std::atomic<bool>& cancel) {
    struct stat st {};
    if (::fstatat(parent_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? PrepareResult::Ready : PrepareResult::Failed;
    }
    if (wants_directory && S_ISDIR(st.st_mode)) return PrepareResult::Ready;
    if (conflict == ConflictPolicy::Skip) return PrepareResult::Skip;
    if (!wants_directory && !S_ISDIR(st.st_mode)) return PrepareResult::Ready;
    return removeAtTree(parent_fd, name, cancel) ? PrepareResult::Ready : PrepareResult::Failed;
}

bool pwriteAll(int fd, const uint8_t* data, size_t size, off_t offset) {
    size_t used = 0;
    while (used < size) {
        ssize_t written = ::pwrite(fd, data + used, size - used, offset + static_cast<off_t>(used));
        if (written > 0) used += static_cast<size_t>(written);
        else if (written < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

EntryMetadata metadataFromEntry(archive_entry* entry, std::vector<std::string> parts) {
    EntryMetadata metadata;
    metadata.parts = std::move(parts);
    metadata.mode = static_cast<mode_t>(archive_entry_perm(entry));
    if (metadata.mode == 0) {
        metadata.mode = archive_entry_filetype(entry) == AE_IFDIR ? 0755 : 0644;
    }
    metadata.uid = archive_entry_uid(entry);
    metadata.gid = archive_entry_gid(entry);
    metadata.has_mtime = archive_entry_mtime_is_set(entry) != 0;
    metadata.mtime.tv_sec = archive_entry_mtime(entry);
    metadata.mtime.tv_nsec = archive_entry_mtime_nsec(entry);

    archive_entry_xattr_reset(entry);
    const char* name = nullptr;
    const void* value = nullptr;
    size_t size = 0;
    while (archive_entry_xattr_next(entry, &name, &value, &size) == ARCHIVE_OK) {
        if (!name || !*name) continue;
        XattrValue xattr;
        xattr.name = name;
        const auto* bytes = static_cast<const uint8_t*>(value);
        if (bytes && size > 0) xattr.value.assign(bytes, bytes + size);
        metadata.xattrs.push_back(std::move(xattr));
    }
    return metadata;
}

void applyFdMetadata(int fd,
                     const EntryMetadata& metadata,
                     JobSnapshot& snapshot,
                     const ArchiveService::Publisher& publish,
                     const std::string& display_path) {
    if ((metadata.uid >= 0 || metadata.gid >= 0)
        && ::fchown(fd, metadata.uid >= 0 ? static_cast<uid_t>(metadata.uid) : static_cast<uid_t>(-1),
                    metadata.gid >= 0 ? static_cast<gid_t>(metadata.gid) : static_cast<gid_t>(-1)) != 0) {
        recordWarning(snapshot, publish, "ARCHIVE_METADATA_WARNING",
                      "fchown failed: " + display_path + ": " + std::strerror(errno), errno);
    }
    if (::fchmod(fd, metadata.mode & 07777) != 0) {
        recordWarning(snapshot, publish, "ARCHIVE_METADATA_WARNING",
                      "fchmod failed: " + display_path + ": " + std::strerror(errno), errno);
    }
    if (metadata.has_mtime) {
        timespec times[2] = {metadata.mtime, metadata.mtime};
        if (::futimens(fd, times) != 0) {
            recordWarning(snapshot, publish, "ARCHIVE_METADATA_WARNING",
                          "futimens failed: " + display_path + ": " + std::strerror(errno), errno);
        }
    }
    for (const auto& xattr : metadata.xattrs) {
        if (::fsetxattr(fd, xattr.name.c_str(), xattr.value.data(), xattr.value.size(), 0) != 0) {
            recordWarning(snapshot, publish, "ARCHIVE_METADATA_WARNING",
                          "fsetxattr failed: " + display_path + ":" + xattr.name
                          + ": " + std::strerror(errno), errno);
        }
    }
}

ScopedFd openExistingDirectory(int root_fd, const std::vector<std::string>& parts) {
    ScopedFd current(::dup(root_fd));
    if (!current) return {};
    for (const auto& part : parts) {
        ScopedFd next(::openat(current.get(), part.c_str(),
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (!next) return {};
        current = std::move(next);
    }
    return current;
}

void markSkip(JobSnapshot& snapshot,
              const ArchiveService::Publisher& publish,
              const std::string& path,
              uint64_t size) {
    snapshot.current_path = path;
    snapshot.skipped_count++;
    snapshot.processed_items++;
    snapshot.processed_bytes += size;
    emit(publish, snapshot);
}

void markSuccess(JobSnapshot& snapshot,
                 const ArchiveService::Publisher& publish,
                 const std::string& path,
                 uint64_t expected_size,
                 uint64_t entry_bytes_start) {
    snapshot.current_path = path;
    snapshot.success_count++;
    snapshot.processed_items++;
    const uint64_t written = snapshot.processed_bytes - entry_bytes_start;
    if (expected_size > written) snapshot.processed_bytes += expected_size - written;
    emit(publish, snapshot);
}

bool archiveDataSkip(archive* reader, JobSnapshot& snapshot,
                     const ArchiveService::Publisher& publish) {
    const int result = archive_read_data_skip(reader);
    if (result < ARCHIVE_WARN) {
        recordError(snapshot, publish, archiveErrorCode(reader),
                    archiveMessage(reader, "Failed to skip archive entry"), archive_errno(reader));
        return false;
    }
    return true;
}

bool extractRegular(archive* reader,
                    archive_entry* entry,
                    int root_fd,
                    const EntryPath& path,
                    const std::string& display_path,
                    ConflictPolicy conflict,
                    std::atomic<bool>& cancel,
                    const ArchiveService::Publisher& publish,
                    JobSnapshot& snapshot) {
    bool parent_skipped = false;
    std::string failed_component;
    ScopedFd parent = openParentDirectory(root_fd, path, conflict, cancel,
                                          parent_skipped, failed_component);
    const uint64_t expected_size = archive_entry_size_is_set(entry) && archive_entry_size(entry) > 0
        ? static_cast<uint64_t>(archive_entry_size(entry)) : 0;
    if (parent_skipped) {
        if (!archiveDataSkip(reader, snapshot, publish)) return false;
        markSkip(snapshot, publish, display_path, expected_size);
        return true;
    }
    if (!parent) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to prepare archive entry parent '" + failed_component + "': "
                    + std::strerror(errno), errno);
        return false;
    }

    const std::string& name = path.parts.back();
    const PrepareResult prepared = prepareLeaf(parent.get(), name, false, conflict, cancel);
    if (prepared == PrepareResult::Skip) {
        if (!archiveDataSkip(reader, snapshot, publish)) return false;
        markSkip(snapshot, publish, display_path, expected_size);
        return true;
    }
    if (prepared == PrepareResult::Failed) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to prepare archive target: " + display_path + ": " + std::strerror(errno), errno);
        return false;
    }

    std::string temp_name;
    ScopedFd output;
    for (int attempt = 0; attempt < 16 && !output; ++attempt) {
        temp_name = ".skroot-extract-" + randomHex(8);
        output.reset(::openat(parent.get(), temp_name.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (!output && errno != EEXIST) break;
    }
    if (!output) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to create temporary extraction file: " + display_path
                    + ": " + std::strerror(errno), errno);
        return false;
    }

    bool ok = true;
    const uint64_t entry_start = snapshot.processed_bytes;
    while (!cancel.load(std::memory_order_acquire)) {
        const void* block = nullptr;
        size_t size = 0;
        la_int64_t offset = 0;
        const int result = archive_read_data_block(reader, &block, &size, &offset);
        if (result == ARCHIVE_EOF) break;
        if (result < ARCHIVE_OK || offset < 0
            || static_cast<uint64_t>(offset) > static_cast<uint64_t>(std::numeric_limits<off_t>::max())
            || size > static_cast<uint64_t>(std::numeric_limits<off_t>::max())
                - static_cast<uint64_t>(offset)) {
            recordError(snapshot, publish, archiveErrorCode(reader),
                        archiveMessage(reader, "Failed to read archive entry"), archive_errno(reader));
            ok = false;
            break;
        }
        if (size > 0 && !pwriteAll(output.get(), static_cast<const uint8_t*>(block), size,
                                   static_cast<off_t>(offset))) {
            const int value = errno;
            recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                        "Failed to write archive entry: " + display_path + ": " + std::strerror(value), value);
            ok = false;
            break;
        }
        snapshot.current_path = display_path;
        snapshot.processed_bytes += size;
        emit(publish, snapshot);
    }
    if (cancel.load(std::memory_order_acquire)) ok = false;

    if (ok && archive_entry_size_is_set(entry) && archive_entry_size(entry) >= 0
        && ::ftruncate(output.get(), static_cast<off_t>(archive_entry_size(entry))) != 0) {
        const int value = errno;
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to size archive entry: " + display_path + ": " + std::strerror(value), value);
        ok = false;
    }
    if (ok) {
        EntryMetadata metadata = metadataFromEntry(entry, {});
        applyFdMetadata(output.get(), metadata, snapshot, publish, display_path);
        if (::fsync(output.get()) != 0) {
            const int value = errno;
            recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                        "Failed to sync archive entry: " + display_path + ": " + std::strerror(value), value);
            ok = false;
        }
    }
    output.reset();
    if (ok && ::renameat(parent.get(), temp_name.c_str(), parent.get(), name.c_str()) != 0) {
        const int value = errno;
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to commit archive entry: " + display_path + ": " + std::strerror(value), value);
        ok = false;
    }
    if (!ok) (void)::unlinkat(parent.get(), temp_name.c_str(), 0);
    if (ok) markSuccess(snapshot, publish, display_path, expected_size, entry_start);
    return ok;
}

bool extractDirectory(archive_entry* entry,
                      int root_fd,
                      const EntryPath& path,
                      const std::string& display_path,
                      ConflictPolicy conflict,
                      std::atomic<bool>& cancel,
                      const ArchiveService::Publisher& publish,
                      JobSnapshot& snapshot,
                      std::vector<EntryMetadata>& directory_metadata) {
    bool parent_skipped = false;
    std::string failed_component;
    ScopedFd parent = openParentDirectory(root_fd, path, conflict, cancel,
                                          parent_skipped, failed_component);
    if (parent_skipped) {
        markSkip(snapshot, publish, display_path, 0);
        return true;
    }
    if (!parent) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to prepare archive directory parent '" + failed_component + "': "
                    + std::strerror(errno), errno);
        return false;
    }
    const std::string& name = path.parts.back();
    const PrepareResult prepared = prepareLeaf(parent.get(), name, true, conflict, cancel);
    if (prepared == PrepareResult::Skip) {
        markSkip(snapshot, publish, display_path, 0);
        return true;
    }
    if (prepared == PrepareResult::Failed
        || (::mkdirat(parent.get(), name.c_str(), 0755) != 0 && errno != EEXIST)) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to create archive directory: " + display_path + ": "
                    + std::strerror(errno), errno);
        return false;
    }
    ScopedFd directory(::openat(parent.get(), name.c_str(),
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!directory) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to open archive directory: " + display_path + ": "
                    + std::strerror(errno), errno);
        return false;
    }
    directory_metadata.push_back(metadataFromEntry(entry, path.parts));
    markSuccess(snapshot, publish, display_path, 0, snapshot.processed_bytes);
    return true;
}

bool extractSymlink(archive* reader,
                    archive_entry* entry,
                    int root_fd,
                    const EntryPath& path,
                    const std::string& display_path,
                    ConflictPolicy conflict,
                    std::atomic<bool>& cancel,
                    const ArchiveService::Publisher& publish,
                    JobSnapshot& snapshot) {
    const char* target = entrySymlink(entry);
    std::vector<std::string> parent_parts(path.parts.begin(), path.parts.end() - 1);
    if (!validContainedSymlink(parent_parts, target)) {
        recordError(snapshot, publish, "ARCHIVE_UNSAFE_LINK",
                    "Archive symlink leaves the extraction directory: " + display_path, EINVAL);
        return false;
    }
    bool parent_skipped = false;
    std::string failed_component;
    ScopedFd parent = openParentDirectory(root_fd, path, conflict, cancel,
                                          parent_skipped, failed_component);
    if (parent_skipped) {
        if (!archiveDataSkip(reader, snapshot, publish)) return false;
        markSkip(snapshot, publish, display_path, 0);
        return true;
    }
    if (!parent) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to prepare symlink parent: " + display_path + ": "
                    + std::strerror(errno), errno);
        return false;
    }
    const std::string& name = path.parts.back();
    const PrepareResult prepared = prepareLeaf(parent.get(), name, false, conflict, cancel);
    if (prepared == PrepareResult::Skip) {
        if (!archiveDataSkip(reader, snapshot, publish)) return false;
        markSkip(snapshot, publish, display_path, 0);
        return true;
    }
    if (prepared == PrepareResult::Failed) {
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to prepare symlink target: " + display_path + ": "
                    + std::strerror(errno), errno);
        return false;
    }
    const std::string temp_name = ".skroot-link-" + randomHex(8);
    if (::symlinkat(target, parent.get(), temp_name.c_str()) != 0
        || ::renameat(parent.get(), temp_name.c_str(), parent.get(), name.c_str()) != 0) {
        const int value = errno;
        (void)::unlinkat(parent.get(), temp_name.c_str(), 0);
        recordError(snapshot, publish, "ARCHIVE_WRITE_FAILED",
                    "Failed to create archive symlink: " + display_path + ": "
                    + std::strerror(value), value);
        return false;
    }
    markSuccess(snapshot, publish, display_path, 0, snapshot.processed_bytes);
    return true;
}

bool scanArchiveEntries(archive* reader,
                        const std::string& archive_path,
                        const std::string& destination,
                        std::atomic<bool>& cancel,
                        const ArchiveService::Publisher& publish,
                        JobSnapshot& snapshot,
                        const ArchiveSelection* selection) {
    bool saw_entry = false;
    uint64_t header_index = 0;
    uint64_t selected_count = 0;
    std::string source_compare = archive_path;
    std::string destination_compare = destination;
    if (selection && selection->enabled) {
        std::array<char, PATH_MAX + 1> resolved {};
        if (::realpath(archive_path.c_str(), resolved.data())) source_compare = resolved.data();
        if (::realpath(destination.c_str(), resolved.data())) destination_compare = resolved.data();
    }
    ArchivePathResolver path_resolver(archive_path);
    while (!cancel.load(std::memory_order_acquire)) {
        archive_entry* entry = nullptr;
        const int result = archive_read_next_header(reader, &entry);
        if (result == ARCHIVE_EOF) break;
        if (result < ARCHIVE_WARN) {
            recordError(snapshot, publish, archiveErrorCode(reader),
                        archiveMessage(reader, "Failed to scan archive"), archive_errno(reader));
            return false;
        }
        if (result == ARCHIVE_WARN) {
            recordWarning(snapshot, publish, "ARCHIVE_READ_WARNING",
                          archiveMessage(reader, "Archive scan warning"), archive_errno(reader));
        }
        saw_entry = true;
        const uint64_t current_index = header_index++;
        if (header_index > kMaxArchiveEntries) {
            recordError(snapshot, publish, "ARCHIVE_TOO_MANY_ENTRIES",
                        "Archive exceeds the 100000 entry limit", EFBIG);
            return false;
        }
        if (!isAllowedFormat(reader)) {
            recordError(snapshot, publish, "ARCHIVE_UNSUPPORTED_FORMAT",
                        "Only ZIP, RAR and 7z archives are supported", EINVAL);
            return false;
        }
        if (archive_entry_is_encrypted(entry) > 0) {
            recordError(snapshot, publish, "ARCHIVE_ENCRYPTED",
                        "Encrypted archives are not supported in this extraction mode", EACCES);
            return false;
        }

        const std::string raw_path = path_resolver.next(entry);
        EntryPath path;
        std::string reason;
        if (!normalizeEntryPath(raw_path.empty() ? nullptr : raw_path.c_str(), path, reason)) {
            recordError(snapshot, publish, "ARCHIVE_UNSAFE_PATH", std::move(reason), EINVAL);
            return false;
        }
        if (path.parts.empty()) continue;
        bool selected = true;
        if (!mapSelectedPath(selection, current_index, path, selected, reason)) {
            recordError(snapshot, publish, "ARCHIVE_CHANGED", std::move(reason), ESTALE);
            return false;
        }
        if (!selected) {
            if (!archiveDataSkip(reader, snapshot, publish)) return false;
            continue;
        }
        ++selected_count;
        const std::string target = (fs::path(destination) / path.relative).lexically_normal().string();
        bool conflicts_with_source = target == archive_path;
        if (selection && selection->enabled) {
            const std::string canonical_target = (fs::path(destination_compare) / path.relative).string();
            struct stat existing {};
            const bool same_inode = ::lstat(target.c_str(), &existing) == 0
                && static_cast<uint64_t>(existing.st_dev) == selection->version.device
                && static_cast<uint64_t>(existing.st_ino) == selection->version.inode;
            const bool removes_source_parent = entryType(entry, raw_path) != AE_IFDIR
                && FileService::isSameOrChildPath(canonical_target, source_compare);
            conflicts_with_source = conflicts_with_source || same_inode || removes_source_parent;
        }
        if (!FileService::isSameOrChildPath(destination, target) || conflicts_with_source) {
            recordError(snapshot, publish, "ARCHIVE_UNSAFE_PATH",
                        "Archive entry conflicts with the archive source or extraction root: " + path.relative,
                        EINVAL);
            return false;
        }
        if (archive_entry_filetype(entry) == AE_IFLNK) {
            std::vector<std::string> parent(path.parts.begin(), path.parts.end() - 1);
            if (!validContainedSymlink(parent, entrySymlink(entry))) {
                recordError(snapshot, publish, "ARCHIVE_UNSAFE_LINK",
                            "Archive symlink leaves the extraction directory: " + path.relative, EINVAL);
                return false;
            }
        }
        ++snapshot.total_items;
        const mode_t type = entryType(entry, raw_path);
        if (type == AE_IFREG && archive_entry_size_is_set(entry)
            && archive_entry_size(entry) > 0) {
            const uint64_t size = static_cast<uint64_t>(archive_entry_size(entry));
            if (snapshot.total_bytes > std::numeric_limits<uint64_t>::max() - size) {
                recordError(snapshot, publish, "ARCHIVE_TOO_LARGE",
                            "Archive expanded size overflows the supported range", EFBIG);
                return false;
            }
            snapshot.total_bytes += size;
        }
        snapshot.current_path = path.relative;
        emit(publish, snapshot);
    }
    if (cancel.load(std::memory_order_acquire)) return false;
    if (selection && selection->enabled && selected_count != selection->entries.size()) {
        recordError(snapshot, publish, "ARCHIVE_CHANGED", "A selected archive entry is missing", ESTALE);
        return false;
    }
    if (!saw_entry && !isAllowedFormat(reader)) {
        recordError(snapshot, publish, "ARCHIVE_UNSUPPORTED_FORMAT",
                    "The selected file is not a ZIP, RAR or 7z archive", EINVAL);
        return false;
    }
    return true;
}

struct ZipTotals {
    uint64_t items = 0;
    uint64_t bytes = 0;
};

bool addZipTotals(const std::string& path,
                  std::atomic<bool>& cancel,
                  ZipTotals& totals,
                  JobSnapshot& snapshot,
                  const ArchiveService::Publisher& publish) {
    if (cancel.load(std::memory_order_acquire)) return false;
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_SCAN_FAILED",
                    "lstat failed: " + path + ": " + std::strerror(value), value);
        return false;
    }
    ++totals.items;
    if (S_ISREG(st.st_mode)) {
        const uint64_t size = st.st_size > 0 ? static_cast<uint64_t>(st.st_size) : 0;
        if (totals.bytes > std::numeric_limits<uint64_t>::max() - size) {
            recordError(snapshot, publish, "ZIP_TOO_LARGE", "ZIP input size overflows supported range", EFBIG);
            return false;
        }
        totals.bytes += size;
    }
    snapshot.current_path = path;
    emit(publish, snapshot);
    if (!S_ISDIR(st.st_mode)) return true;
    DIR* dir = openDirectoryNoFollow(path);
    if (!dir) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_SCAN_FAILED",
                    "opendir failed: " + path + ": " + std::strerror(value), value);
        return false;
    }
    bool ok = true;
    while (!cancel.load(std::memory_order_acquire)) {
        errno = 0;
        dirent* entry = ::readdir(dir);
        if (!entry) {
            if (errno != 0) {
                const int value = errno;
                recordError(snapshot, publish, "ZIP_SCAN_FAILED",
                            "readdir failed: " + path + ": " + std::strerror(value), value);
                ok = false;
            }
            break;
        }
        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;
        const std::string child = (fs::path(path) / entry->d_name).lexically_normal().string();
        if (!addZipTotals(child, cancel, totals, snapshot, publish)) ok = false;
    }
    ::closedir(dir);
    return ok && !cancel.load(std::memory_order_acquire);
}

void setZipEntryMetadata(archive_entry* entry, const struct stat& st) {
    archive_entry_set_perm(entry, st.st_mode & 07777);
    archive_entry_set_uid(entry, static_cast<la_int64_t>(st.st_uid));
    archive_entry_set_gid(entry, static_cast<la_int64_t>(st.st_gid));
#if defined(__APPLE__)
    archive_entry_set_mtime(entry, st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
#else
    archive_entry_set_mtime(entry, st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
#endif
}

bool zipWriteData(archive* writer, const std::string& path, const std::string& display_path,
                  std::atomic<bool>& cancel, JobSnapshot& snapshot,
                  const ArchiveService::Publisher& publish) {
    ScopedFd input(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!input) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_READ_FAILED",
                    "open failed: " + display_path + ": " + std::strerror(value), value);
        return false;
    }
    std::array<uint8_t, 128 * 1024> buffer {};
    while (!cancel.load(std::memory_order_acquire)) {
        const ssize_t value = ::read(input.get(), buffer.data(), buffer.size());
        if (value > 0) {
            size_t written = 0;
            while (written < static_cast<size_t>(value)) {
                const la_ssize_t out = archive_write_data(writer, buffer.data() + written,
                                                          static_cast<size_t>(value) - written);
                if (out <= 0) {
                    const int saved = errno == 0 ? EIO : errno;
                    recordError(snapshot, publish, "ZIP_WRITE_FAILED",
                                "archive write failed: " + display_path, saved);
                    return false;
                }
                written += static_cast<size_t>(out);
            }
            snapshot.processed_bytes += static_cast<uint64_t>(value);
            snapshot.current_path = display_path;
            emit(publish, snapshot);
            continue;
        }
        if (value == 0) return true;
        if (errno == EINTR) continue;
        const int saved = errno;
        recordError(snapshot, publish, "ZIP_READ_FAILED",
                    "read failed: " + display_path + ": " + std::strerror(saved), saved);
        return false;
    }
    return false;
}

bool writeZipTree(archive* writer, const std::string& path, const std::string& relative,
                  std::atomic<bool>& cancel, JobSnapshot& snapshot,
                  const ArchiveService::Publisher& publish) {
    if (cancel.load(std::memory_order_acquire)) return false;
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_READ_FAILED",
                    "lstat failed: " + path + ": " + std::strerror(value), value);
        return false;
    }
    snapshot.current_path = path;
    archive_entry* raw_entry = archive_entry_new();
    if (!raw_entry) {
        recordError(snapshot, publish, "ZIP_INIT_FAILED", "Failed to allocate ZIP entry", ENOMEM);
        return false;
    }
    std::unique_ptr<archive_entry, decltype(&archive_entry_free)> entry(raw_entry, archive_entry_free);
    archive_entry_set_pathname_utf8(entry.get(), relative.c_str());
    setZipEntryMetadata(entry.get(), st);
    const bool is_dir = S_ISDIR(st.st_mode);
    const bool is_file = S_ISREG(st.st_mode);
    const bool is_link = S_ISLNK(st.st_mode);
    if (is_dir) {
        archive_entry_set_filetype(entry.get(), AE_IFDIR);
        archive_entry_set_size(entry.get(), 0);
    } else if (is_file) {
        archive_entry_set_filetype(entry.get(), AE_IFREG);
        archive_entry_set_size(entry.get(), st.st_size > 0 ? static_cast<la_int64_t>(st.st_size) : 0);
    } else if (is_link) {
        std::array<char, PATH_MAX + 1> link_target {};
        const ssize_t length = ::readlink(path.c_str(), link_target.data(), link_target.size() - 1);
        if (length < 0) {
            const int value = errno;
            recordError(snapshot, publish, "ZIP_READ_FAILED",
                        "readlink failed: " + path + ": " + std::strerror(value), value);
            return false;
        }
        link_target[static_cast<size_t>(length)] = '\0';
        archive_entry_set_filetype(entry.get(), AE_IFLNK);
        archive_entry_set_symlink_utf8(entry.get(), link_target.data());
        archive_entry_set_size(entry.get(), 0);
    } else {
        recordWarning(snapshot, publish, "ZIP_UNSUPPORTED_ENTRY",
                      "Special file skipped: " + path, EOPNOTSUPP);
        snapshot.skipped_count++;
        snapshot.processed_items++;
        emit(publish, snapshot);
        return true;
    }
    if (archive_write_header(writer, entry.get()) < ARCHIVE_OK) {
        const int value = errno == 0 ? EIO : errno;
        recordError(snapshot, publish, "ZIP_WRITE_FAILED", "Failed to write ZIP header: " + relative, value);
        return false;
    }
    bool ok = true;
    if (is_file) ok = zipWriteData(writer, path, path, cancel, snapshot, publish);
    if (archive_write_finish_entry(writer) < ARCHIVE_OK) {
        const int value = errno == 0 ? EIO : errno;
        recordError(snapshot, publish, "ZIP_WRITE_FAILED", "Failed to finish ZIP entry: " + relative, value);
        ok = false;
    }
    if (!ok || cancel.load(std::memory_order_acquire)) return false;
    snapshot.processed_items++;
    snapshot.success_count++;
    emit(publish, snapshot);
    if (!is_dir) return true;
    DIR* dir = openDirectoryNoFollow(path);
    if (!dir) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_READ_FAILED",
                    "opendir failed: " + path + ": " + std::strerror(value), value);
        return false;
    }
    while (!cancel.load(std::memory_order_acquire)) {
        errno = 0;
        dirent* child = ::readdir(dir);
        if (!child) {
            if (errno != 0) {
                const int value = errno;
                recordError(snapshot, publish, "ZIP_READ_FAILED",
                            "readdir failed: " + path + ": " + std::strerror(value), value);
                ::closedir(dir);
                return false;
            }
            break;
        }
        if (std::strcmp(child->d_name, ".") == 0 || std::strcmp(child->d_name, "..") == 0) continue;
        const std::string child_path = (fs::path(path) / child->d_name).lexically_normal().string();
        const std::string child_relative = relative + "/" + child->d_name;
        if (!writeZipTree(writer, child_path, child_relative, cancel, snapshot, publish)) {
            ::closedir(dir);
            return false;
        }
    }
    ::closedir(dir);
    return !cancel.load(std::memory_order_acquire);
}

bool renameZipNoReplace(const std::string& source, const std::string& target) {
#if defined(__NR_renameat2) && defined(RENAME_NOREPLACE)
    if (::syscall(__NR_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD, target.c_str(), RENAME_NOREPLACE) == 0) {
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP && errno != ENOTSUP) return false;
#endif
    const int reservation = ::open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (reservation < 0) return false;
    ::close(reservation);
    if (::rename(source.c_str(), target.c_str()) == 0) return true;
    const int value = errno;
    (void)::unlink(target.c_str());
    errno = value;
    return false;
}

std::string nextZipName(const std::string& requested, int index) {
    if (index == 0) return requested;
    const fs::path path(requested);
    const std::string stem = path.stem().string();
    return (path.parent_path() / (stem + " (" + std::to_string(index) + ").zip")).string();
}

std::string archiveBaseName(const std::string& path) {
    return fs::path(path).filename().string();
}

bool syncZipParent(const std::string& path) {
    const fs::path parent = fs::path(path).parent_path().empty()
        ? fs::path("/") : fs::path(path).parent_path();
    const int fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

} // namespace

bool ArchiveService::index(const std::string& archive_path,
                           const FileVersion& version,
                           std::atomic<bool>& cancel_requested,
                           const std::function<void(uint64_t)>& progress,
                           std::vector<ArchiveIndexEntry>& entries,
                           Error& error) {
    entries.clear();
    error = {};
    ScopedUtf8Locale locale_guard;
    JobSnapshot diagnostics;
    const Publisher discard = [](const JobSnapshot&) {};
    ScopedFd source;
    ArchivePtr reader = openArchive(archive_path, diagnostics, discard, &source, &version);
    if (!reader) {
        error = diagnostics.errors.empty() ? Error{"ARCHIVE_READ_FAILED", "Unable to open archive", EIO}
                                           : diagnostics.errors.front();
        return false;
    }
    ArchivePathResolver path_resolver(archive_path, kMaxArchiveIndexTextBytes, &cancel_requested);
    if (path_resolver.tooLarge()) {
        error = {"ARCHIVE_INDEX_TOO_LARGE", "Archive index exceeds the 16 MiB pathname limit", EFBIG};
        return false;
    }
    uint64_t header_index = 0;
    size_t text_bytes = 0;
    const auto fail = [&](std::string code, std::string message, int value) {
        error = {std::move(code), std::move(message), value};
        entries.clear();
        return false;
    };
    while (!cancel_requested.load(std::memory_order_acquire)) {
        archive_entry* entry = nullptr;
        const int result = archive_read_next_header(reader.get(), &entry);
        if (result == ARCHIVE_EOF) break;
        if (result < ARCHIVE_WARN) {
            return fail(archiveErrorCode(reader.get()), archiveMessage(reader.get(), "Failed to index archive"),
                        archive_errno(reader.get()));
        }
        if (!isAllowedFormat(reader.get())) {
            return fail("ARCHIVE_UNSUPPORTED_FORMAT", "Only single-volume ZIP, RAR and 7z archives are supported", EINVAL);
        }
        if (header_index >= kMaxArchiveIndexEntries) {
            return fail("ARCHIVE_INDEX_TOO_LARGE", "Archive exceeds the 100000 entry index limit", EFBIG);
        }
        const uint64_t current_index = header_index++;
        if (archive_entry_is_encrypted(entry) > 0) {
            return fail("ARCHIVE_ENCRYPTED", "Encrypted archives are not supported", EACCES);
        }
        const std::string raw_path = path_resolver.next(entry);
        EntryPath path;
        std::string reason;
        if (!normalizeEntryPath(raw_path.c_str(), path, reason)) {
            return fail("ARCHIVE_UNSAFE_PATH", std::move(reason), EINVAL);
        }
        if (!path.parts.empty()) {
            ArchiveIndexEntry item;
            item.header_index = current_index;
            item.path = std::move(path.relative);
            const mode_t type = entryType(entry, raw_path);
            item.type = archive_entry_hardlink(entry) ? "hardlink"
                : type == AE_IFDIR ? "directory" : type == AE_IFREG ? "file"
                : type == AE_IFLNK ? "symlink" : "special";
            if (type == AE_IFREG && archive_entry_size_is_set(entry) && archive_entry_size(entry) > 0) {
                item.size = static_cast<uint64_t>(archive_entry_size(entry));
            }
            if (archive_entry_mtime_is_set(entry)) {
                const int64_t seconds = archive_entry_mtime(entry);
                if (seconds >= std::numeric_limits<int64_t>::min() / 1000
                    && seconds <= std::numeric_limits<int64_t>::max() / 1000 - 1) {
                    item.mtime_ms = seconds * 1000 + archive_entry_mtime_nsec(entry) / 1000000;
                }
            }
            if (type == AE_IFLNK) {
                const char* target = entrySymlink(entry);
                std::vector<std::string> parent(path.parts.begin(), path.parts.end() - 1);
                if (!validContainedSymlink(parent, target)) {
                    return fail("ARCHIVE_UNSAFE_LINK", "Archive symlink leaves the archive root: " + item.path, EINVAL);
                }
                item.symlink_target = target;
            }
            const size_t bytes = item.path.size() + item.symlink_target.size();
            if (bytes > kMaxArchiveIndexTextBytes - text_bytes) {
                return fail("ARCHIVE_INDEX_TOO_LARGE", "Archive index exceeds the 16 MiB pathname limit", EFBIG);
            }
            text_bytes += bytes;
            entries.push_back(std::move(item));
        }
        if ((header_index & 63) == 0 && progress) progress(header_index);
        // Solid archives may need to decode preceding content to reach a later
        // header. Skipping through libarchive preserves its format-specific logic.
        if (!archiveDataSkip(reader.get(), diagnostics, discard)) {
            error = diagnostics.errors.back();
            entries.clear();
            return false;
        }
    }
    if (cancel_requested.load(std::memory_order_acquire)) {
        return fail("ARCHIVE_CANCELLED", "Archive indexing was cancelled", ECANCELED);
    }
    if (!isAllowedFormat(reader.get())) {
        return fail("ARCHIVE_UNSUPPORTED_FORMAT", "The selected file is not a ZIP, RAR or 7z archive", EINVAL);
    }
    if (!versionUnchanged(archive_path, version)) {
        return fail("ARCHIVE_CHANGED", "Archive changed while indexing; reopen it", ESTALE);
    }
    if (progress) progress(header_index);
    return true;
}

bool ArchiveService::isSupportedSingleArchivePath(const std::string& path) {
    const std::string name = lowerName(path);
    if (name.size() >= 4 && name.compare(name.size() - 4, 4, ".zip") == 0) {
        return !hasCompanionVolume(path);
    }
    if (name.size() >= 3 && name.compare(name.size() - 3, 3, ".7z") == 0) {
        return !hasCompanionVolume(path);
    }
    if (name.size() < 4 || name.compare(name.size() - 4, 4, ".rar") != 0) return false;
    const std::string stem = name.substr(0, name.size() - 4);
    const size_t part = stem.rfind(".part");
    if (part != std::string::npos && isDigits(std::string_view(stem).substr(part + 5))) return false;
    return !hasCompanionVolume(path);
}

bool ArchiveService::scan(const std::string& archive_path,
                          const std::string& destination,
                          std::atomic<bool>& cancel_requested,
                          const Publisher& publish,
                          JobSnapshot& snapshot,
                          const ArchiveSelection* selection) {
    ScopedUtf8Locale locale_guard;
    ScopedFd source;
    const FileVersion* version = selection && selection->enabled ? &selection->version : nullptr;
    ArchivePtr reader = openArchive(archive_path, snapshot, publish, &source, version);
    if (!reader) return false;
    const bool scanned = scanArchiveEntries(reader.get(), archive_path, destination,
                                            cancel_requested, publish, snapshot, selection);
    if (scanned && version && !versionUnchanged(archive_path, *version)) {
        recordError(snapshot, publish, "ARCHIVE_CHANGED", "Archive changed while scanning", ESTALE);
        return false;
    }
    return scanned;
}

bool ArchiveService::extract(const std::string& archive_path,
                             const std::string& destination,
                             ConflictPolicy conflict,
                             std::atomic<bool>& cancel_requested,
                             const Publisher& publish,
                             JobSnapshot& snapshot,
                             const ArchiveSelection* selection) {
    ScopedUtf8Locale locale_guard;
    struct stat root_stat {};
    if (::lstat(destination.c_str(), &root_stat) != 0 || !S_ISDIR(root_stat.st_mode)) {
        const int value = errno == 0 ? ENOTDIR : errno;
        recordError(snapshot, publish, "INVALID_DESTINATION",
                    "Extraction destination is not a real directory: " + destination, value);
        return false;
    }
    ScopedFd root(::open(destination.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!root) {
        recordError(snapshot, publish, "INVALID_DESTINATION",
                    "Failed to open extraction destination: " + destination + ": "
                    + std::strerror(errno), errno);
        return false;
    }
    struct statvfs space {};
    if (::fstatvfs(root.get(), &space) == 0) {
        const uint64_t block_size = static_cast<uint64_t>(space.f_frsize ? space.f_frsize : space.f_bsize);
        const uint64_t blocks = static_cast<uint64_t>(space.f_bavail);
        const uint64_t available = block_size != 0
            && blocks > std::numeric_limits<uint64_t>::max() / block_size
            ? std::numeric_limits<uint64_t>::max() : blocks * block_size;
        if (snapshot.total_bytes > available) {
            recordError(snapshot, publish, "ARCHIVE_NO_SPACE",
                        "Archive expanded size exceeds destination free space", ENOSPC);
            return false;
        }
    }

    ScopedFd source;
    const FileVersion* version = selection && selection->enabled ? &selection->version : nullptr;
    ArchivePtr reader = openArchive(archive_path, snapshot, publish, &source, version);
    if (!reader) return false;
    ArchivePathResolver path_resolver(archive_path);
    std::vector<EntryMetadata> directory_metadata;
    bool all_ok = true;
    uint64_t header_index = 0;
    uint64_t selected_count = 0;
    while (!cancel_requested.load(std::memory_order_acquire)) {
        archive_entry* entry = nullptr;
        const int result = archive_read_next_header(reader.get(), &entry);
        if (result == ARCHIVE_EOF) break;
        if (result < ARCHIVE_WARN) {
            recordError(snapshot, publish, archiveErrorCode(reader.get()),
                        archiveMessage(reader.get(), "Failed to read archive header"),
                        archive_errno(reader.get()));
            all_ok = false;
            break;
        }
        if (result == ARCHIVE_WARN) {
            recordWarning(snapshot, publish, "ARCHIVE_READ_WARNING",
                          archiveMessage(reader.get(), "Archive read warning"), archive_errno(reader.get()));
        }

        const uint64_t current_index = header_index++;
        const std::string raw_path = path_resolver.next(entry);
        EntryPath path;
        std::string reason;
        if (!normalizeEntryPath(raw_path.empty() ? nullptr : raw_path.c_str(), path, reason)
            || path.parts.empty()) {
            if (!path.parts.empty() || !reason.empty()) {
                recordError(snapshot, publish, "ARCHIVE_UNSAFE_PATH", std::move(reason), EINVAL);
                all_ok = false;
                break;
            }
            continue;
        }
        bool selected = true;
        if (!mapSelectedPath(selection, current_index, path, selected, reason)) {
            recordError(snapshot, publish, "ARCHIVE_CHANGED", std::move(reason), ESTALE);
            all_ok = false;
            break;
        }
        if (!selected) {
            if (!archiveDataSkip(reader.get(), snapshot, publish)) { all_ok = false; break; }
            continue;
        }
        ++selected_count;
        if (version && !versionUnchanged(archive_path, *version)) {
            recordError(snapshot, publish, "ARCHIVE_CHANGED", "Archive changed while extracting", ESTALE);
            all_ok = false;
            break;
        }
        const std::string display_path = (fs::path(destination) / path.relative).string();
        snapshot.current_path = display_path;
        emit(publish, snapshot);

        const mode_t type = entryType(entry, raw_path);
        bool entry_ok = true;
        if (archive_entry_hardlink(entry)) {
            if (!archiveDataSkip(reader.get(), snapshot, publish)) {
                all_ok = false;
                break;
            }
            recordWarning(snapshot, publish, "ARCHIVE_UNSUPPORTED_ENTRY",
                          "Hardlink entry was skipped: " + display_path);
            markSkip(snapshot, publish, display_path, 0);
        } else if (type == AE_IFDIR) {
            entry_ok = extractDirectory(entry, root.get(), path, display_path, conflict,
                                        cancel_requested, publish, snapshot, directory_metadata);
        } else if (type == AE_IFREG) {
            entry_ok = extractRegular(reader.get(), entry, root.get(), path, display_path,
                                      conflict, cancel_requested, publish, snapshot);
        } else if (type == AE_IFLNK) {
            entry_ok = extractSymlink(reader.get(), entry, root.get(), path, display_path,
                                      conflict, cancel_requested, publish, snapshot);
        } else {
            if (!archiveDataSkip(reader.get(), snapshot, publish)) {
                all_ok = false;
                break;
            }
            recordWarning(snapshot, publish, "ARCHIVE_UNSUPPORTED_ENTRY",
                          "Special archive entry was skipped: " + display_path);
            markSkip(snapshot, publish, display_path, 0);
        }
        if (!entry_ok) all_ok = false;
        if (cancel_requested.load(std::memory_order_acquire)) break;
    }

    if (all_ok && selection && selection->enabled && selected_count != selection->entries.size()) {
        recordError(snapshot, publish, "ARCHIVE_CHANGED", "A selected archive entry is missing", ESTALE);
        all_ok = false;
    }
    if (all_ok && version && !versionUnchanged(archive_path, *version)) {
        recordError(snapshot, publish, "ARCHIVE_CHANGED", "Archive changed while extracting", ESTALE);
        all_ok = false;
    }
    for (auto it = directory_metadata.rbegin(); it != directory_metadata.rend(); ++it) {
        if (cancel_requested.load(std::memory_order_acquire)) break;
        ScopedFd directory = openExistingDirectory(root.get(), it->parts);
        if (!directory) {
            recordWarning(snapshot, publish, "ARCHIVE_METADATA_WARNING",
                          "Directory metadata target disappeared: "
                          + (fs::path(destination) / fs::path(it->parts.front())).string(), errno);
            continue;
        }
        std::string relative;
        for (const auto& part : it->parts) {
            if (!relative.empty()) relative.push_back('/');
            relative += part;
        }
        applyFdMetadata(directory.get(), *it, snapshot, publish,
                        (fs::path(destination) / relative).string());
        (void)::fsync(directory.get());
    }
    (void)::fsync(root.get());
    return all_ok && !cancel_requested.load(std::memory_order_acquire);
}

bool ArchiveService::compress(const std::vector<std::string>& sources,
                              const std::string& output_path,
                              std::atomic<bool>& cancel_requested,
                              const Publisher& publish,
                              JobSnapshot& snapshot) {
    ScopedUtf8Locale locale_guard;
    ZipTotals totals;
    for (const auto& source : sources) {
        if (!addZipTotals(source, cancel_requested, totals, snapshot, publish)) return false;
    }
    if (cancel_requested.load(std::memory_order_acquire)) return false;
    snapshot.total_items = totals.items;
    snapshot.total_bytes = totals.bytes;
    emit(publish, snapshot);

    const std::string temp = (fs::path(output_path).parent_path()
        / (".skroot-zip-" + randomHex(8))).string();
    ScopedFd temp_fd(::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!temp_fd) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_CREATE_FAILED",
                    std::string("Failed to create ZIP temporary file: ") + std::strerror(value), value);
        return false;
    }
    ArchiveWriterPtr writer(archive_write_new());
    if (!writer || archive_write_set_format_zip(writer.get()) != ARCHIVE_OK
        || archive_write_add_filter_none(writer.get()) != ARCHIVE_OK
        || archive_write_zip_set_compression_deflate(writer.get()) != ARCHIVE_OK
        || archive_write_open_fd(writer.get(), temp_fd.get()) != ARCHIVE_OK) {
        const int value = errno == 0 ? EIO : errno;
        recordError(snapshot, publish, "ZIP_INIT_FAILED", "Failed to initialize ZIP writer", value);
        (void)::unlink(temp.c_str());
        return false;
    }
    snapshot.state = "running";
    emit(publish, snapshot);
    bool ok = true;
    for (const auto& source : sources) {
        if (!writeZipTree(writer.get(), source, archiveBaseName(source), cancel_requested, snapshot, publish)) {
            ok = false;
            break;
        }
    }
    if (ok && !cancel_requested.load(std::memory_order_acquire)
        && archive_write_close(writer.get()) != ARCHIVE_OK) {
        recordError(snapshot, publish, "ZIP_WRITE_FAILED", "Failed to finalize ZIP archive", EIO);
        ok = false;
    }
    if (!ok || cancel_requested.load(std::memory_order_acquire)) {
        archive_write_fail(writer.get());
    }
    writer.reset();
    if (ok && ::fsync(temp_fd.get()) != 0) {
        const int value = errno;
        recordError(snapshot, publish, "ZIP_WRITE_FAILED",
                    std::string("Failed to sync ZIP archive: ") + std::strerror(value), value);
        ok = false;
    }
    temp_fd.reset();
    if (cancel_requested.load(std::memory_order_acquire)) ok = false;
    if (ok) {
        for (int attempt = 0; attempt < 1000; ++attempt) {
            const std::string candidate = nextZipName(output_path, attempt);
            if (renameZipNoReplace(temp, candidate)) {
                snapshot.output_path = candidate;
                (void)syncZipParent(candidate);
                return true;
            }
            if (errno != EEXIST) break;
        }
        const int value = errno == 0 ? EEXIST : errno;
        recordError(snapshot, publish, "ZIP_COMMIT_FAILED",
                    std::string("Failed to commit ZIP archive: ") + std::strerror(value), value);
        ok = false;
    }
    (void)::unlink(temp.c_str());
    return ok;
}

} // namespace file_manager
