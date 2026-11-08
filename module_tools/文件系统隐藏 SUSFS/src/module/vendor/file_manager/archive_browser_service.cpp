#include "archive_browser_service.h"

#include "list_dir_helper.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <condition_variable>
#include <deque>
#include <exception>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace file_manager {
namespace {

constexpr size_t kMaxBrowserSessions = 2;
constexpr size_t kMaxBrowserPage = 500;

bool fail(Error& error, const char* code, const char* message, int value = EINVAL) {
    error = {code, message, value};
    return false;
}

std::string parentOf(const std::string& path) {
    const size_t slash = path.rfind('/');
    return slash == std::string::npos ? std::string{} : path.substr(0, slash);
}

std::string nameOf(const std::string& path) {
    const size_t slash = path.rfind('/');
    return path.substr(slash == std::string::npos ? 0 : slash + 1);
}

bool normalizeInnerPath(const std::string& path, std::string& result, Error& error) {
    result.clear();
    if (path.empty() || path == "/") return true;
    if (path.size() >= PATH_MAX || path.front() == '/' || path.back() == '/'
        || path.find('\\') != std::string::npos || path.find('\0') != std::string::npos
        || !TextTransferService::isValidUtf8(reinterpret_cast<const uint8_t*>(path.data()), path.size())) {
        return fail(error, "INVALID_ARCHIVE_PATH", "Archive directory must be a normalized relative path");
    }
    size_t start = 0;
    while (start < path.size()) {
        const size_t slash = path.find('/', start);
        const std::string part = path.substr(start, slash == std::string::npos ? slash : slash - start);
        if (part.empty() || part == "." || part == ".." || part.size() > NAME_MAX) {
            return fail(error, "INVALID_ARCHIVE_PATH", "Archive directory contains an invalid component");
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    result = path;
    return true;
}

bool currentVersion(const std::string& path, const FileVersion& expected, Error& error) {
    FileVersion current;
    Error ignored;
    if (!TextTransferService::getVersion(path, current, ignored) || current != expected) {
        return fail(error, "ARCHIVE_CHANGED", "Archive changed; refresh to reopen it", ESTALE);
    }
    return true;
}

struct BrowserIndex {
    std::vector<ArchiveIndexEntry> physical;
    std::vector<ArchiveBrowserEntry> nodes;
    std::unordered_map<std::string, size_t> ids;
    std::unordered_map<std::string, std::vector<size_t>> children;
};

bool buildTree(BrowserIndex& index, const std::atomic<bool>& cancelled, Error& error) {
    std::unordered_map<std::string, size_t> directories;
    std::unordered_map<std::string, uint64_t> duplicates;
    size_t text_bytes = 0;
    for (const auto& item : index.physical) text_bytes += item.path.size() + item.symlink_target.size();
    index.children[""] = {};
    const auto addNode = [&](ArchiveBrowserEntry item) {
        const std::string parent = parentOf(item.path);
        // Count owned pathname text, including lookup keys, rather than only the
        // original headers. A very deep tree otherwise multiplies memory use.
        size_t bytes = item.id.size() * 2 + item.name.size() + item.path.size();
        if (index.children.find(parent) == index.children.end()) bytes += parent.size();
        if (item.type == "directory") bytes += item.path.size() * 2;
        if (index.nodes.size() >= kMaxArchiveIndexEntries || text_bytes > kMaxArchiveIndexTextBytes
            || bytes > kMaxArchiveIndexTextBytes - text_bytes) {
            return fail(error, "ARCHIVE_INDEX_TOO_LARGE", "Archive index exceeds the 100000 node or 16 MiB pathname limit", EFBIG);
        }
        text_bytes += bytes;
        const size_t position = index.nodes.size();
        index.ids.emplace(item.id, position);
        index.children[parent].push_back(position);
        if (item.type == "directory") {
            directories.emplace(item.path, position);
            index.children.try_emplace(item.path);
        }
        index.nodes.push_back(std::move(item));
        return true;
    };
    const auto ensureDirectory = [&](const std::string& path, bool implicit, int64_t modified) {
        const auto found = directories.find(path);
        if (found != directories.end()) {
            if (!implicit) {
                auto& node = index.nodes[found->second];
                node.is_implicit = false;
                node.mtime_ms = modified;
            }
            return true;
        }
        ArchiveBrowserEntry node;
        node.id = "d:" + path;
        node.name = nameOf(path);
        node.path = path;
        node.type = "directory";
        node.is_implicit = implicit;
        node.mtime_ms = modified;
        return addNode(std::move(node));
    };
    for (const auto& entry : index.physical) {
        if (cancelled.load(std::memory_order_acquire)) {
            return fail(error, "ARCHIVE_CANCELLED", "Archive indexing was cancelled", ECANCELED);
        }
        for (size_t slash = entry.path.find('/'); slash != std::string::npos;
             slash = entry.path.find('/', slash + 1)) {
            if (!ensureDirectory(entry.path.substr(0, slash), true, 0)) return false;
        }
        if (entry.type == "directory") {
            if (!ensureDirectory(entry.path, false, entry.mtime_ms)) return false;
            continue;
        }
        ArchiveBrowserEntry node;
        node.id = "e:" + std::to_string(entry.header_index);
        node.name = nameOf(entry.path);
        node.path = entry.path;
        node.type = entry.type;
        node.size = entry.size;
        node.mtime_ms = entry.mtime_ms;
        node.duplicate_index = ++duplicates[entry.path];
        node.selectable = entry.type == "file" || entry.type == "symlink";
        if (!addNode(std::move(node))) return false;
    }
    for (auto& [path, children] : index.children) {
        if (cancelled.load(std::memory_order_acquire)) {
            return fail(error, "ARCHIVE_CANCELLED", "Archive indexing was cancelled", ECANCELED);
        }
        std::stable_sort(children.begin(), children.end(), [&](size_t left, size_t right) {
            const auto& a = index.nodes[left];
            const auto& b = index.nodes[right];
            if ((a.type == "directory") != (b.type == "directory")) return a.type == "directory";
            return a.name < b.name;
        });
    }
    return true;
}

} // namespace

struct ArchiveBrowserService::Impl {
    struct Session {
        ArchiveBrowserStatus status;
        std::atomic<bool> cancel{false};
        std::shared_ptr<const BrowserIndex> index;
    };

    mutable std::mutex mutex;
    std::mutex lifecycle;
    std::condition_variable wake;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions;
    std::deque<std::shared_ptr<Session>> queued;
    std::shared_ptr<Session> active;
    // The monitor must cancel indexing without waiting behind filesystem I/O
    // performed while the session mutex is held by a foreground request.
    std::shared_ptr<Session> monitored_active;
    std::atomic<bool> stop_requested{false};
    std::string special_comm;
    bool stopping = false;
    std::thread worker;

    std::shared_ptr<Session> find(const std::string& id, Error& error) {
        const auto found = sessions.find(id);
        if (found == sessions.end()) {
            fail(error, "ARCHIVE_SESSION_NOT_FOUND", "Archive browsing session was closed; reopen the archive", ENOENT);
            return {};
        }
        return found->second;
    }

    bool ready(const std::shared_ptr<Session>& session, Error& error) {
        if (session->status.state == "failed") { error = session->status.error; return false; }
        if (session->status.state != "ready") {
            return fail(error, "ARCHIVE_NOT_READY", "Archive index is still being prepared", EBUSY);
        }
        list_dir_helper::ScopedProcComm guard;
        if (!special_comm.empty()) guard.set_temp(special_comm);
        if (!currentVersion(session->status.archive_path, session->status.version, error)) {
            session->status.state = "failed";
            session->status.error = error;
            session->index.reset();
            return false;
        }
        return true;
    }

    void run() {
        for (;;) {
            std::shared_ptr<Session> session;
            std::string comm;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait(lock, [this] { return stopping || stop_requested.load(std::memory_order_acquire) || !queued.empty(); });
                if (stopping || stop_requested.load(std::memory_order_acquire)) return;
                session = queued.front();
                queued.pop_front();
                if (session->cancel.load(std::memory_order_acquire)) continue;
                active = session;
                std::atomic_store_explicit(&monitored_active, session, std::memory_order_release);
                if (stop_requested.load(std::memory_order_acquire)) session->cancel.store(true, std::memory_order_release);
                session->status.state = "scanning";
                comm = special_comm;
            }
            list_dir_helper::ScopedProcComm guard;
            if (!comm.empty()) guard.set_temp(comm);
            std::shared_ptr<BrowserIndex> built;
            Error error;
            bool ok = false;
            try {
                built = std::make_shared<BrowserIndex>();
                ok = ArchiveService::index(session->status.archive_path, session->status.version,
                    session->cancel, [this, session](uint64_t count) {
                        std::lock_guard<std::mutex> lock(mutex);
                        session->status.scanned_entries = count;
                    }, built->physical, error);
                if (ok) ok = buildTree(*built, session->cancel, error);
                if (ok) ok = currentVersion(session->status.archive_path, session->status.version, error);
            } catch (const std::bad_alloc&) {
                ok = false;
                error = {"ARCHIVE_INDEX_TOO_LARGE", "Not enough memory for the archive index", ENOMEM};
            } catch (const std::exception& exception) {
                ok = false;
                error = {"ARCHIVE_READ_FAILED", exception.what(), EIO};
            }
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (!session->cancel.load(std::memory_order_acquire)) {
                    session->status.state = ok ? "ready" : "failed";
                    session->status.error = error;
                    if (ok) {
                        session->status.total_entries = session->status.scanned_entries;
                        session->status.total_nodes = built->nodes.size();
                        session->index = std::move(built);
                    }
                }
                active.reset();
                std::atomic_store_explicit(&monitored_active, std::shared_ptr<Session>{}, std::memory_order_release);
            }
        }
    }
};

ArchiveBrowserService::ArchiveBrowserService() : m_impl(std::make_unique<Impl>()) {}
ArchiveBrowserService::~ArchiveBrowserService() { shutdown(); }

void ArchiveBrowserService::setSpecialComm(std::string special_comm) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->special_comm = std::move(special_comm);
}

bool ArchiveBrowserService::open(const std::string& path, ArchiveBrowserStatus& result, Error& error) {
    // The WebUI creates its service members before forking the terminal child.
    // Start background work only when the first browser request arrives.
    std::lock_guard<std::mutex> lifecycle(m_impl->lifecycle);
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->stopping || m_impl->stop_requested.load(std::memory_order_acquire))
        return fail(error, "ARCHIVE_SERVICE_CLOSED", "Archive browser is shutting down", EBUSY);
    if (m_impl->sessions.size() >= kMaxBrowserSessions) {
        return fail(error, "ARCHIVE_SESSION_LIMIT", "At most two archives can be open; close one first", EBUSY);
    }
    std::string normalized;
    if (!FileService::normalizeAbsolutePath(path, normalized, error)) return false;
    list_dir_helper::ScopedProcComm guard;
    if (!m_impl->special_comm.empty()) guard.set_temp(m_impl->special_comm);
    if (!ArchiveService::isSupportedSingleArchivePath(normalized)) {
        return fail(error, "ARCHIVE_UNSUPPORTED_FORMAT", "Only single-volume .zip, .rar and .7z files are supported");
    }
    FileVersion version;
    if (!TextTransferService::getVersion(normalized, version, error)) return false;
    if (!m_impl->worker.joinable()) {
        try {
            m_impl->worker = std::thread([this] { m_impl->run(); });
        } catch (const std::system_error&) {
            return fail(error, "ARCHIVE_THREAD_FAILED", "Unable to start archive indexing", EAGAIN);
        }
    }
    auto session = std::make_shared<Impl::Session>();
    session->status.session_id = randomHex(16);
    session->status.archive_path = normalized;
    session->status.version = version;
    session->status.state = "queued";
    m_impl->sessions.emplace(session->status.session_id, session);
    m_impl->queued.push_back(session);
    result = session->status;
    m_impl->wake.notify_one();
    return true;
}

bool ArchiveBrowserService::status(const std::string& session_id, ArchiveBrowserStatus& result, Error& error) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const auto session = m_impl->find(session_id, error);
    if (!session) return false;
    if (session->status.state == "ready") {
        Error changed;
        (void)m_impl->ready(session, changed);
    }
    result = session->status;
    return true;
}

bool ArchiveBrowserService::list(const std::string& session_id, const std::string& inner_path,
                                 uint64_t offset, size_t limit, ArchiveBrowserList& result, Error& error) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const auto session = m_impl->find(session_id, error);
    if (!session || !m_impl->ready(session, error)) return false;
    std::string path;
    if (!normalizeInnerPath(inner_path, path, error)) return false;
    const auto children = session->index->children.find(path);
    if (children == session->index->children.end()) {
        return fail(error, "ARCHIVE_DIRECTORY_NOT_FOUND", "Archive directory does not exist", ENOENT);
    }
    if (limit == 0 || limit > kMaxBrowserPage || offset > children->second.size()) {
        return fail(error, "INVALID_ARGUMENT", "Archive page limit must be 1 to 500 and offset must be within the directory");
    }
    result = {};
    result.session_id = session_id;
    result.inner_path = path;
    result.offset = offset;
    result.total = children->second.size();
    result.next_offset = std::min<uint64_t>(result.total, offset + limit);
    result.eof = result.next_offset == result.total;
    for (uint64_t i = offset; i < result.next_offset; ++i) {
        result.entries.push_back(session->index->nodes[children->second[static_cast<size_t>(i)]]);
    }
    return true;
}

bool ArchiveBrowserService::close(const std::string& session_id, Error& error) {
    (void)error;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const auto found = m_impl->sessions.find(session_id);
    if (found == m_impl->sessions.end()) return true;
    found->second->cancel.store(true, std::memory_order_release);
    m_impl->queued.erase(std::remove(m_impl->queued.begin(), m_impl->queued.end(), found->second), m_impl->queued.end());
    m_impl->sessions.erase(found);
    return true;
}

bool ArchiveBrowserService::resolveSelection(const std::string& session_id, const std::string& base_path,
                                             const std::vector<std::string>& entry_ids,
                                             ArchiveSelection& result, Error& error) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const auto session = m_impl->find(session_id, error);
    if (!session || !m_impl->ready(session, error)) return false;
    std::string base;
    if (!normalizeInnerPath(base_path, base, error)) return false;
    if (entry_ids.empty() || entry_ids.size() > kMaxOperationSources) {
        return fail(error, "INVALID_ARCHIVE_SELECTION", "Select between 1 and 500 archive items");
    }
    std::unordered_set<std::string> files;
    std::unordered_set<std::string> directories;
    for (const auto& id : entry_ids) {
        const auto found = session->index->ids.find(id);
        if (found == session->index->ids.end()) {
            return fail(error, "INVALID_ARCHIVE_SELECTION", "A selected archive item does not exist");
        }
        const auto& node = session->index->nodes[found->second];
        if (parentOf(node.path) != base || !node.selectable) {
            return fail(error, "INVALID_ARCHIVE_SELECTION", "Select supported items from the current archive directory only");
        }
        if (node.type == "directory") directories.insert(node.path);
        else files.insert(id);
    }
    result = {};
    result.enabled = true;
    result.archive_path = session->status.archive_path;
    result.version = session->status.version;
    result.base_path = base;
    for (const auto& entry : session->index->physical) {
        bool selected = files.find("e:" + std::to_string(entry.header_index)) != files.end();
        if (!selected && !directories.empty()) {
            const std::string relative = base.empty() ? entry.path
                : entry.path.compare(0, base.size() + 1, base + "/") == 0
                    ? entry.path.substr(base.size() + 1) : std::string{};
            if (!relative.empty()) {
                const size_t slash = relative.find('/');
                const std::string child = (base.empty() ? "" : base + "/") + relative.substr(0, slash);
                selected = directories.find(child) != directories.end()
                    && (entry.path != child || entry.type == "directory");
            }
        }
        if (selected) result.entries.push_back({entry.header_index, entry.path});
    }
    if (result.entries.empty()) return fail(error, "INVALID_ARCHIVE_SELECTION", "The selection contains no archive entries");
    return true;
}

bool ArchiveBrowserService::isActive() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return bool(m_impl->active) || !m_impl->queued.empty();
}

void ArchiveBrowserService::shutdown() {
    std::lock_guard<std::mutex> lifecycle(m_impl->lifecycle);
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->stopping = true;
        for (const auto& [id, session] : m_impl->sessions) session->cancel.store(true, std::memory_order_release);
        if (m_impl->active) m_impl->active->cancel.store(true, std::memory_order_release);
        m_impl->queued.clear();
        m_impl->sessions.clear();
    }
    m_impl->wake.notify_all();
    if (m_impl->worker.joinable()) m_impl->worker.join();
}

void ArchiveBrowserService::requestStop() {
    m_impl->stop_requested.store(true, std::memory_order_release);
    const auto active = std::atomic_load_explicit(&m_impl->monitored_active, std::memory_order_acquire);
    if (active) active->cancel.store(true, std::memory_order_release);
    m_impl->wake.notify_all();
}

} // namespace file_manager
