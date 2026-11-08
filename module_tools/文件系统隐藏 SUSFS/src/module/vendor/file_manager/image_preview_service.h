#pragma once

#include "file_manager_service.h"

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace file_manager {

constexpr uint64_t kMaxImageFileBytes = 32ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxImagePixels = 32000000ULL;
constexpr uint32_t kMaxImageDimension = 32768;

struct ImageOpenResult {
    std::string session_id;
    std::string path;
    uint64_t size = 0;
    std::string mime;
    uint32_t width = 0;
    uint32_t height = 0;
    FileVersion version;
};

// Read-only, bounded transfers through the authenticated file API. No file
// descriptor or decoded bitmap is retained between requests.
class ImagePreviewService {
public:
    using Clock = std::chrono::steady_clock;
    explicit ImagePreviewService(std::function<Clock::time_point()> now = Clock::now);
    ~ImagePreviewService();

    bool openImage(const std::string& path, ImageOpenResult& result, Error& error);
    bool readChunk(const std::string& session_id, uint64_t offset, size_t limit,
                   TextReadResult& result, Error& error);
    void close(const std::string& session_id);
    void shutdown();

private:
    struct Session {
        std::string path;
        FileVersion version;
        Clock::time_point touched;
    };
    void expire(Clock::time_point now);

    std::mutex m_mu;
    std::unordered_map<std::string, Session> m_sessions;
    std::function<Clock::time_point()> m_now;
    bool m_shutdown = false;
};

} // namespace file_manager
