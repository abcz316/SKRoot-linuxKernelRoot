#include "image_preview_service.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace file_manager {
namespace {

constexpr size_t kMaxImageSessions = 8;
constexpr auto kImageSessionLifetime = std::chrono::minutes(5);
constexpr size_t kMaxHeaderSegments = 8192;

struct ScopedFd {
    int value = -1;
    ~ScopedFd() { if (value >= 0) ::close(value); }
};

bool fail(Error& error, const char* code, const char* message, int value = 0) {
    error = {code, message, value};
    return false;
}

FileVersion versionOf(const struct stat& st) {
    return {static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino),
            static_cast<uint64_t>(st.st_size), st.st_mtim.tv_sec, st.st_mtim.tv_nsec};
}

bool statRegular(const std::string& path, FileVersion& version, Error& error) {
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0)
        return fail(error, "STAT_FAILED", "Unable to inspect image file", errno);
    if (!S_ISREG(st.st_mode) || st.st_size < 0)
        return fail(error, "NOT_REGULAR_FILE", "Image preview requires a regular file");
    version = versionOf(st);
    return true;
}

bool checkVersion(int fd, const std::string& path, const FileVersion& expected, Error& error) {
    struct stat st {};
    if (::fstat(fd, &st) != 0)
        return fail(error, "STAT_FAILED", "Unable to inspect opened image file", errno);
    FileVersion current;
    if (!statRegular(path, current, error)) return false;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || versionOf(st) != expected || current != expected)
        return fail(error, "FILE_CHANGED", "The image changed while it was being read", EBUSY);
    return true;
}

bool readExact(int fd, uint64_t size, uint64_t offset, uint8_t* output, size_t count, Error& error) {
    if (offset > size || count > size - offset)
        return fail(error, "INVALID_IMAGE", "The image header is incomplete");
    size_t used = 0;
    while (used < count) {
        const ssize_t n = ::pread(fd, output + used, count - used, static_cast<off_t>(offset + used));
        if (n > 0) used += static_cast<size_t>(n);
        else if (n < 0 && errno == EINTR) continue;
        else if (n < 0) return fail(error, "READ_FAILED", "Unable to read image file", errno);
        else return fail(error, "FILE_CHANGED", "The image was truncated while it was being read", EBUSY);
    }
    return true;
}

uint32_t le16(const uint8_t* p) { return p[0] | (static_cast<uint32_t>(p[1]) << 8); }
uint32_t be16(const uint8_t* p) { return (static_cast<uint32_t>(p[0]) << 8) | p[1]; }
uint32_t le24(const uint8_t* p) { return le16(p) | (static_cast<uint32_t>(p[2]) << 16); }
uint32_t le32(const uint8_t* p) { return le24(p) | (static_cast<uint32_t>(p[3]) << 24); }
uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
        | (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

bool jpegDimensions(int fd, uint64_t size, ImageOpenResult& result, Error& error) {
    uint64_t offset = 2;
    for (size_t segment = 0; segment < kMaxHeaderSegments && offset < size; ++segment) {
        std::array<uint8_t, 9> bytes {};
        if (!readExact(fd, size, offset++, bytes.data(), 1, error)) return false;
        if (bytes[0] != 0xff) break;
        do {
            if (!readExact(fd, size, offset++, bytes.data(), 1, error)) return false;
        } while (bytes[0] == 0xff && offset < size);
        const uint8_t marker = bytes[0];
        if (marker == 0xd9 || marker == 0xda || marker == 0x00) break;
        if (marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
        if (!readExact(fd, size, offset, bytes.data(), 2, error)) return false;
        const uint32_t length = be16(bytes.data());
        if (length < 2 || length > size - offset) break;
        const bool sof = marker >= 0xc0 && marker <= 0xcf
            && marker != 0xc4 && marker != 0xc8 && marker != 0xcc;
        if (sof) {
            if (length < 11 || !readExact(fd, size, offset, bytes.data(), 8, error)) break;
            if (!bytes[7] || length != 8U + 3U * bytes[7]) break;
            result.height = be16(bytes.data() + 3);
            result.width = be16(bytes.data() + 5);
            result.mime = "image/jpeg";
            return true;
        }
        offset += length;
    }
    return fail(error, "INVALID_IMAGE", "JPEG has no valid size header");
}

bool webpDimensions(int fd, uint64_t size, const uint8_t* head,
                    ImageOpenResult& result, Error& error) {
    const uint64_t riff_end = static_cast<uint64_t>(le32(head + 4)) + 8;
    if (riff_end > size || riff_end < 20)
        return fail(error, "INVALID_IMAGE", "WebP container is incomplete");
    uint64_t offset = 12;
    for (size_t chunk = 0; chunk < kMaxHeaderSegments && offset + 8 <= riff_end; ++chunk) {
        std::array<uint8_t, 18> bytes {};
        if (!readExact(fd, riff_end, offset, bytes.data(), 8, error)) return false;
        const uint32_t payload_size = le32(bytes.data() + 4);
        if (payload_size > riff_end - offset - 8)
            return fail(error, "INVALID_IMAGE", "WebP chunk is incomplete");
        const bool extended = std::memcmp(bytes.data(), "VP8X", 4) == 0;
        const bool lossy = std::memcmp(bytes.data(), "VP8 ", 4) == 0;
        const bool lossless = std::memcmp(bytes.data(), "VP8L", 4) == 0;
        const size_t needed = lossless ? 5 : 10;
        if (extended || lossy || lossless) {
            if (payload_size < needed || !readExact(fd, riff_end, offset + 8, bytes.data() + 8, needed, error))
                return fail(error, "INVALID_IMAGE", "WebP size header is incomplete");
            const uint8_t* p = bytes.data() + 8;
            if (extended) {
                if (payload_size != 10) return fail(error, "INVALID_IMAGE", "Invalid WebP extended header");
                result.width = le24(p + 4) + 1;
                result.height = le24(p + 7) + 1;
            } else if (lossy) {
                if ((p[0] & 1) || p[3] != 0x9d || p[4] != 0x01 || p[5] != 0x2a)
                    return fail(error, "INVALID_IMAGE", "Invalid WebP frame header");
                result.width = le16(p + 6) & 0x3fff;
                result.height = le16(p + 8) & 0x3fff;
            } else {
                if (p[0] != 0x2f || (p[4] & 0xe0))
                    return fail(error, "INVALID_IMAGE", "Invalid WebP lossless header");
                const uint32_t dimensions = le32(p + 1);
                result.width = (dimensions & 0x3fff) + 1;
                result.height = ((dimensions >> 14) & 0x3fff) + 1;
            }
            result.mime = "image/webp";
            return true;
        }
        offset += 8ULL + payload_size + (payload_size & 1U);
    }
    return fail(error, "INVALID_IMAGE", "WebP has no valid size header");
}

bool inspectImage(int fd, uint64_t size, ImageOpenResult& result, Error& error) {
    std::array<uint8_t, 64> head {};
    const size_t count = static_cast<size_t>(std::min<uint64_t>(size, head.size()));
    if (!readExact(fd, size, 0, head.data(), count, error)) return false;
    const uint8_t* p = head.data();
    if (count >= 8 && std::memcmp(p, "\x89PNG\r\n\x1a\n", 8) == 0) {
        if (count < 33 || be32(p + 8) != 13 || std::memcmp(p + 12, "IHDR", 4) != 0)
            return fail(error, "INVALID_IMAGE", "PNG has no valid size header");
        result.mime = "image/png";
        result.width = be32(p + 16);
        result.height = be32(p + 20);
    } else if (count >= 6 && (!std::memcmp(p, "GIF87a", 6) || !std::memcmp(p, "GIF89a", 6))) {
        if (count < 13) return fail(error, "INVALID_IMAGE", "GIF size header is incomplete");
        result.mime = "image/gif";
        result.width = le16(p + 6);
        result.height = le16(p + 8);
    } else if (count >= 2 && p[0] == 0xff && p[1] == 0xd8) {
        if (!jpegDimensions(fd, size, result, error)) return false;
    } else if (count >= 12 && !std::memcmp(p, "RIFF", 4) && !std::memcmp(p + 8, "WEBP", 4)) {
        if (!webpDimensions(fd, size, p, result, error)) return false;
    } else if (count >= 2 && p[0] == 'B' && p[1] == 'M') {
        if (count < 26) return fail(error, "INVALID_IMAGE", "BMP size header is incomplete");
        const uint32_t dib_size = le32(p + 14);
        if (dib_size > size - 14 || le32(p + 10) < 14ULL + dib_size || le32(p + 10) > size)
            return fail(error, "INVALID_IMAGE", "Invalid BMP bitmap offset");
        if (dib_size == 12) {
            result.width = le16(p + 18);
            result.height = le16(p + 20);
        } else if (dib_size >= 40 && count >= 54) {
            const uint32_t width = le32(p + 18);
            const uint32_t height = le32(p + 22);
            if (width & 0x80000000U) return fail(error, "INVALID_IMAGE", "Invalid BMP width");
            result.width = width;
            result.height = (height & 0x80000000U) ? (~height + 1U) : height;
        } else return fail(error, "INVALID_IMAGE", "Unsupported BMP size header");
        result.mime = "image/bmp";
    } else return fail(error, "IMAGE_UNSUPPORTED_FORMAT", "Preview supports PNG, JPEG, GIF, WebP and BMP images");

    if (!result.width || !result.height)
        return fail(error, "INVALID_IMAGE", "The image has zero width or height");
    if (result.width > kMaxImageDimension || result.height > kMaxImageDimension
        || static_cast<uint64_t>(result.width) * result.height > kMaxImagePixels)
        return fail(error, "IMAGE_DIMENSIONS_TOO_LARGE", "Image exceeds 32 million pixels or 32768 pixels per side");
    return true;
}

} // namespace

ImagePreviewService::ImagePreviewService(std::function<Clock::time_point()> now) : m_now(std::move(now)) {}
ImagePreviewService::~ImagePreviewService() { shutdown(); }

void ImagePreviewService::expire(Clock::time_point now) {
    for (auto it = m_sessions.begin(); it != m_sessions.end();) {
        if (now - it->second.touched >= kImageSessionLifetime) it = m_sessions.erase(it);
        else ++it;
    }
}

bool ImagePreviewService::openImage(const std::string& input, ImageOpenResult& result, Error& error) {
    ImageOpenResult opened;
    if (!FileService::normalizeAbsolutePath(input, opened.path, error)) return false;
    if (!statRegular(opened.path, opened.version, error)) return false;
    if (opened.version.size > kMaxImageFileBytes)
        return fail(error, "IMAGE_TOO_LARGE", "Image file exceeds 32 MiB");
    // O_NONBLOCK prevents a concurrent replacement with a FIFO from hanging open.
    ScopedFd fd {::open(opened.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    if (fd.value < 0) return fail(error, "OPEN_FAILED", "Unable to open image file", errno);
    if (!checkVersion(fd.value, opened.path, opened.version, error)) return false;
    opened.size = opened.version.size;
    if (!inspectImage(fd.value, opened.size, opened, error)) return false;
    if (!checkVersion(fd.value, opened.path, opened.version, error)) return false;

    std::lock_guard<std::mutex> lock(m_mu);
    if (m_shutdown) return fail(error, "IMAGE_SERVICE_CLOSED", "Image preview service is closed");
    const auto now = m_now();
    expire(now);
    if (m_sessions.size() >= kMaxImageSessions) {
        const auto oldest = std::min_element(m_sessions.begin(), m_sessions.end(),
            [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
        m_sessions.erase(oldest);
    }
    do { opened.session_id = randomHex(12); } while (m_sessions.count(opened.session_id));
    m_sessions.emplace(opened.session_id, Session {opened.path, opened.version, now});
    result = std::move(opened);
    return true;
}

bool ImagePreviewService::readChunk(const std::string& id, uint64_t offset, size_t limit,
                                  TextReadResult& result, Error& error) {
    std::lock_guard<std::mutex> lock(m_mu);
    const auto now = m_now();
    expire(now);
    const auto session = m_sessions.find(id);
    if (session == m_sessions.end())
        return fail(error, "IMAGE_SESSION_NOT_FOUND", "Image preview session expired or was closed", ENOENT);
    const auto& value = session->second;
    if (offset > value.version.size)
        return fail(error, "INVALID_OFFSET", "Read offset is beyond the end of the image", EINVAL);
    ScopedFd fd {::open(value.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    if (fd.value < 0) {
        m_sessions.erase(session);
        return fail(error, "OPEN_FAILED", "Unable to reopen image file", errno);
    }
    if (!checkVersion(fd.value, value.path, value.version, error)) {
        m_sessions.erase(session);
        return false;
    }
    limit = std::min(limit ? limit : kMaxTransferChunkBytes, kMaxTransferChunkBytes);
    std::vector<uint8_t> bytes(static_cast<size_t>(std::min<uint64_t>(limit, value.version.size - offset)));
    if (!readExact(fd.value, value.version.size, offset, bytes.data(), bytes.size(), error)
        || !checkVersion(fd.value, value.path, value.version, error)) {
        m_sessions.erase(session);
        return false;
    }
    result.offset = offset;
    result.next_offset = offset + bytes.size();
    result.eof = result.next_offset == value.version.size;
    result.base64_data = TextTransferService::encodeBase64(bytes.data(), bytes.size());
    if (result.eof) m_sessions.erase(session);
    else session->second.touched = now;
    return true;
}

void ImagePreviewService::close(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mu);
    expire(m_now());
    m_sessions.erase(id);
}

void ImagePreviewService::shutdown() {
    std::lock_guard<std::mutex> lock(m_mu);
    m_shutdown = true;
    m_sessions.clear();
}

} // namespace file_manager
