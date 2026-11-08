#include "file_manager_api.h"

#include "cJSON.h"
#include "module_base_disk_storage.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <set>

namespace file_manager {
namespace {

using JsonPtr = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;

JsonPtr makeJson(cJSON* value) {
    return JsonPtr(value, cJSON_Delete);
}

std::string printJson(const cJSON* value) {
    char* text = cJSON_PrintUnformatted(value);
    if (!text) return "{}";
    std::string result(text);
    cJSON_free(text);
    return result;
}

ApiReply envelope(int status,
                  bool ok,
                  const std::string& code,
                  const std::string& message,
                  int sys_errno,
                  cJSON* data = nullptr) {
    auto root = makeJson(cJSON_CreateObject());
    cJSON_AddBoolToObject(root.get(), "ok", ok);
    cJSON_AddStringToObject(root.get(), "code", code.c_str());
    cJSON_AddStringToObject(root.get(), "message", message.c_str());
    cJSON_AddNumberToObject(root.get(), "errno", sys_errno);
    cJSON_AddStringToObject(root.get(), "requestId", randomHex(8).c_str());
    if (data) cJSON_AddItemToObject(root.get(), "data", data);
    else cJSON_AddItemToObject(root.get(), "data", cJSON_CreateNull());
    return {status, printJson(root.get())};
}

ApiReply success(cJSON* data = nullptr, int status = 200) {
    return envelope(status, true, "OK", "", 0, data);
}

int statusForError(const Error& error) {
    if (error.code == "READ_ONLY_FILE") return 403;
    if (error.code == "IMAGE_SESSION_NOT_FOUND" || error.code == "ARCHIVE_SESSION_NOT_FOUND") return 404;
    if (error.code == "IMAGE_TOO_LARGE" || error.code == "IMAGE_DIMENSIONS_TOO_LARGE" || error.code == "ARCHIVE_INDEX_TOO_LARGE") return 413;
    if (error.code == "IMAGE_UNSUPPORTED_FORMAT" || error.code == "INVALID_IMAGE") return 422;
    if (error.code == "ARCHIVE_CHANGED" || error.code == "ARCHIVE_NOT_READY" || error.code == "ARCHIVE_SESSION_LIMIT") return 409;
    if (error.code == "JOB_NOT_FOUND" || error.code == "TEXT_SESSION_NOT_FOUND"
        || error.code == "SAVE_SESSION_NOT_FOUND") return 404;
    if (error.code == "TARGET_EXISTS" || error.code == "FILE_CHANGED"
        || error.code == "JOB_BUSY" || error.code == "SAVE_BUSY") return 409;
    if (error.code == "TEXT_TOO_LARGE" || error.code == "CHUNK_TOO_LARGE"
        || error.code == "INVALID_UTF8" || error.code == "ARCHIVE_UNSUPPORTED_FORMAT"
        || error.code == "ARCHIVE_ENCRYPTED" || error.code == "ARCHIVE_NO_SPACE"
        || error.code == "ARCHIVE_UNSAFE_PATH" || error.code == "ARCHIVE_UNSAFE_LINK") return 422;
    if (error.code == "INVALID_APK") return 400;
    if (error.code == "ARCHIVE_TOO_MANY_ENTRIES" || error.code == "ARCHIVE_TOO_LARGE") return 413;
    if (error.code.rfind("INVALID_", 0) == 0 || error.code == "INCOMPLETE_SAVE"
        || error.code == "NOT_DIRECTORY" || error.code == "NOT_REGULAR_FILE"
        || error.code == "ROOT_OPERATION_BLOCKED") return 400;
    return 500;
}

JsonPtr parseObject(const std::string& body, Error& error) {
    auto root = makeJson(cJSON_ParseWithLength(body.data(), body.size()));
    if (!root || !cJSON_IsObject(root.get())) {
        error = {"INVALID_JSON", "Request body must be a JSON object", EINVAL};
        return makeJson(nullptr);
    }
    return root;
}

bool getString(cJSON* root, const char* name, std::string& out, Error& error, bool required = true) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!value && !required) {
        out.clear();
        return true;
    }
    if (!cJSON_IsString(value) || !value->valuestring) {
        error = {"INVALID_ARGUMENT", std::string("Field '") + name + "' must be a string", EINVAL};
        return false;
    }
    out = value->valuestring;
    return true;
}

bool getBool(cJSON* root, const char* name, bool& out, Error& error, bool default_value) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!value) {
        out = default_value;
        return true;
    }
    if (!cJSON_IsBool(value)) {
        error = {"INVALID_ARGUMENT", std::string("Field '") + name + "' must be a boolean", EINVAL};
        return false;
    }
    out = cJSON_IsTrue(value);
    return true;
}

bool getUint64(cJSON* root, const char* name, uint64_t& out, Error& error, uint64_t default_value = 0) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!value) {
        out = default_value;
        return true;
    }
    if (!cJSON_IsNumber(value) || !std::isfinite(value->valuedouble)
        || value->valuedouble < 0 || std::floor(value->valuedouble) != value->valuedouble
        || value->valuedouble > 9007199254740991.0) {
        error = {"INVALID_ARGUMENT", std::string("Field '") + name + "' must be a non-negative number", EINVAL};
        return false;
    }
    out = static_cast<uint64_t>(value->valuedouble);
    return true;
}

bool parseModeString(const std::string& value, uint32_t& mode) {
    if (value.size() < 3 || value.size() > 4
        || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return ch >= '0' && ch <= '7';
        })) return false;
    mode = 0;
    for (char ch : value) mode = (mode << 3) | static_cast<uint32_t>(ch - '0');
    return mode <= 07777;
}

std::string octalMode(uint32_t mode) {
    char value[8] = {};
    std::snprintf(value, sizeof(value), "%04o", mode & 07777);
    return value;
}

std::string symbolicMode(uint32_t mode) {
    std::string value = "---------";
    if (mode & 0400) value[0] = 'r';
    if (mode & 0200) value[1] = 'w';
    if (mode & 0100) value[2] = 'x';
    if (mode & 0040) value[3] = 'r';
    if (mode & 0020) value[4] = 'w';
    if (mode & 0010) value[5] = 'x';
    if (mode & 0004) value[6] = 'r';
    if (mode & 0002) value[7] = 'w';
    if (mode & 0001) value[8] = 'x';
    if (mode & 04000) value[2] = (mode & 0100) ? 's' : 'S';
    if (mode & 02000) value[5] = (mode & 0010) ? 's' : 'S';
    if (mode & 01000) value[8] = (mode & 0001) ? 't' : 'T';
    return value;
}

bool parseSignedString(cJSON* root, const char* name, int64_t& out) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(value) || !value->valuestring) return false;
    char* end = nullptr;
    errno = 0;
    long long parsed = std::strtoll(value->valuestring, &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    out = static_cast<int64_t>(parsed);
    return true;
}

bool parseUnsignedString(cJSON* root, const char* name, uint64_t& out) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(value) || !value->valuestring || value->valuestring[0] == '\0'
        || value->valuestring[0] == '-') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(value->valuestring, &end, 10);
    if (errno != 0 || !end || *end != '\0') return false;
    out = static_cast<uint64_t>(parsed);
    return true;
}

cJSON* versionJson(const FileVersion& version) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "device", std::to_string(version.device).c_str());
    cJSON_AddStringToObject(root, "inode", std::to_string(version.inode).c_str());
    cJSON_AddStringToObject(root, "size", std::to_string(version.size).c_str());
    cJSON_AddStringToObject(root, "mtimeSec", std::to_string(version.mtime_sec).c_str());
    cJSON_AddStringToObject(root, "mtimeNsec", std::to_string(version.mtime_nsec).c_str());
    return root;
}

bool parseVersion(cJSON* root, FileVersion& version, Error& error) {
    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!cJSON_IsObject(value)
        || !parseUnsignedString(value, "device", version.device)
        || !parseUnsignedString(value, "inode", version.inode)
        || !parseUnsignedString(value, "size", version.size)
        || !parseSignedString(value, "mtimeSec", version.mtime_sec)
        || !parseSignedString(value, "mtimeNsec", version.mtime_nsec)) {
        error = {"INVALID_ARGUMENT", "Field 'version' is missing or invalid", EINVAL};
        return false;
    }
    return true;
}

cJSON* errorJson(const Error& error) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "code", error.code.c_str());
    cJSON_AddStringToObject(item, "message", error.message.c_str());
    cJSON_AddNumberToObject(item, "errno", error.sys_errno);
    return item;
}

cJSON* jobJson(const JobSnapshot& job) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "id", job.id.c_str());
    cJSON_AddStringToObject(root, "state", job.state.c_str());
    cJSON_AddStringToObject(root, "operation", job.operation.c_str());
    cJSON_AddStringToObject(root, "currentPath", job.current_path.c_str());
    cJSON_AddStringToObject(root, "outputPath", job.output_path.c_str());
    cJSON_AddNumberToObject(root, "exitCode", job.exit_code);
    cJSON_AddStringToObject(root, "resultCode", job.result_code.c_str());
    cJSON_AddStringToObject(root, "resultMessage", job.result_message.c_str());
    cJSON_AddNumberToObject(root, "totalBytes", static_cast<double>(job.total_bytes));
    cJSON_AddNumberToObject(root, "processedBytes", static_cast<double>(job.processed_bytes));
    cJSON_AddNumberToObject(root, "totalItems", static_cast<double>(job.total_items));
    cJSON_AddNumberToObject(root, "processedItems", static_cast<double>(job.processed_items));
    cJSON_AddNumberToObject(root, "successCount", static_cast<double>(job.success_count));
    cJSON_AddNumberToObject(root, "skippedCount", static_cast<double>(job.skipped_count));
    cJSON_AddNumberToObject(root, "failedCount", static_cast<double>(job.failed_count));
    cJSON_AddNumberToObject(root, "warningCount", static_cast<double>(job.warning_count));
    cJSON* errors = cJSON_CreateArray();
    for (const auto& error : job.errors) cJSON_AddItemToArray(errors, errorJson(error));
    cJSON_AddItemToObject(root, "errors", errors);
    cJSON* warnings = cJSON_CreateArray();
    for (const auto& warning : job.warnings) cJSON_AddItemToArray(warnings, errorJson(warning));
    cJSON_AddItemToObject(root, "warnings", warnings);
    return root;
}

struct PlaceEntry {
    std::string path;
    std::string note;
};

constexpr const char* kPlacesStorageKey = "file_manager_places_v1";
constexpr size_t kMaxBookmarks = 200;
constexpr size_t kMaxRecent = 20;
constexpr size_t kMaxPlaceInputItems = 500;
constexpr size_t kMaxBookmarkNoteBytes = 512;

bool parsePlaceArray(cJSON* array,
                     bool include_note,
                     bool strict,
                     size_t output_limit,
                     std::vector<PlaceEntry>& output,
                     Error& error) {
    if (!cJSON_IsArray(array)) {
        if (!strict) return true;
        error = {"INVALID_ARGUMENT", include_note
            ? "Field 'bookmarks' must be an array" : "Field 'recent' must be an array", EINVAL};
        return false;
    }
    if (cJSON_GetArraySize(array) > static_cast<int>(kMaxPlaceInputItems)) {
        error = {"INVALID_ARGUMENT", "Too many bookmark or recent items", E2BIG};
        return false;
    }

    std::set<std::string> seen;
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, array) {
        if (!cJSON_IsObject(item)) {
            if (strict) {
                error = {"INVALID_ARGUMENT", "Bookmark and recent items must be objects", EINVAL};
                return false;
            }
            continue;
        }
        cJSON* path_item = cJSON_GetObjectItemCaseSensitive(item, "path");
        if (!cJSON_IsString(path_item) || !path_item->valuestring) {
            if (strict) {
                error = {"INVALID_ARGUMENT", "Place item path must be a string", EINVAL};
                return false;
            }
            continue;
        }
        std::string normalized;
        Error normalize_error;
        if (!FileService::normalizeAbsolutePath(path_item->valuestring, normalized, normalize_error)) {
            if (strict) {
                error = normalize_error;
                return false;
            }
            continue;
        }
        if (!seen.insert(normalized).second || output.size() >= output_limit) continue;

        PlaceEntry place;
        place.path = std::move(normalized);
        if (include_note) {
            cJSON* note_item = cJSON_GetObjectItemCaseSensitive(item, "note");
            if (note_item) {
                if (!cJSON_IsString(note_item) || !note_item->valuestring) {
                    if (strict) {
                        error = {"INVALID_ARGUMENT", "Bookmark note must be a string", EINVAL};
                        return false;
                    }
                    continue;
                }
                place.note = note_item->valuestring;
                if (place.note.size() > kMaxBookmarkNoteBytes) {
                    if (strict) {
                        error = {"INVALID_ARGUMENT", "Bookmark note is too long", E2BIG};
                        return false;
                    }
                    place.note.clear();
                }
            }
        }
        output.push_back(std::move(place));
    }
    return true;
}

cJSON* placesJson(const std::vector<PlaceEntry>& bookmarks, const std::vector<PlaceEntry>& recent) {
    cJSON* data = cJSON_CreateObject();
    cJSON* bookmark_array = cJSON_CreateArray();
    for (const auto& bookmark : bookmarks) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "path", bookmark.path.c_str());
        cJSON_AddStringToObject(item, "note", bookmark.note.c_str());
        cJSON_AddItemToArray(bookmark_array, item);
    }
    cJSON_AddItemToObject(data, "bookmarks", bookmark_array);

    cJSON* recent_array = cJSON_CreateArray();
    for (const auto& place : recent) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "path", place.path.c_str());
        cJSON_AddItemToArray(recent_array, item);
    }
    cJSON_AddItemToObject(data, "recent", recent_array);
    return data;
}

void readStoredPlaces(std::vector<PlaceEntry>& bookmarks, std::vector<PlaceEntry>& recent) {
    std::string stored;
    (void)kernel_module::read_string_disk_storage(kPlacesStorageKey, stored);
    auto root = makeJson(cJSON_Parse(stored.c_str()));
    if (!root || !cJSON_IsObject(root.get())) return;
    Error ignored;
    (void)parsePlaceArray(cJSON_GetObjectItemCaseSensitive(root.get(), "bookmarks"),
                          true, false, kMaxBookmarks, bookmarks, ignored);
    ignored = {};
    (void)parsePlaceArray(cJSON_GetObjectItemCaseSensitive(root.get(), "recent"),
                          false, false, kMaxRecent, recent, ignored);
}

ApiReply busyReply() {
    return makeApiError({"JOB_BUSY", "A file operation is currently running", EBUSY});
}

} // namespace

ApiReply makeApiError(const Error& error, int status) {
    return envelope(status > 0 ? status : statusForError(error), false,
                    error.code.empty() ? "INTERNAL_ERROR" : error.code,
                    error.message.empty() ? "File operation failed" : error.message,
                    error.sys_errno);
}

FileManagerApi::FileManagerApi() : m_jobs(m_files) {}

FileManagerApi::~FileManagerApi() {
    shutdown();
}

void FileManagerApi::configure(const std::string& special_comm) {
    m_files.setSpecialComm(special_comm);
    m_archives.setSpecialComm(special_comm);
}

ApiReply FileManagerApi::handle(const std::string& path, const std::string& body) {
    if (m_stop_requested.load(std::memory_order_acquire))
        return makeApiError({"FILE_SERVICE_STOPPED", "File service is stopping; reopen the WebUI", ECANCELED}, 503);
    const bool write_route = path == "/api/files/settings/set-home"
        || path == "/api/files/places/set"
        || path == "/api/files/mkdir" || path == "/api/files/create" || path == "/api/files/rename"
        || path == "/api/files/job/start" || path == "/api/files/job/cancel"
        || path.rfind("/api/files/text/save/", 0) == 0;
    std::unique_lock<std::mutex> write_lk(m_write_mu, std::defer_lock);
    if (write_route) write_lk.lock();
    if (m_stop_requested.load(std::memory_order_acquire))
        return makeApiError({"FILE_SERVICE_STOPPED", "File service is stopping; reopen the WebUI", ECANCELED}, 503);
    if (path == "/api/files/image/open") return handleImageOpen(body);
    if (path == "/api/files/image/read") return handleImageRead(body);
    if (path == "/api/files/image/close") return handleImageClose(body);
    if (path.rfind("/api/files/archive/", 0) == 0) return handleArchive(path, body);
    if (path == "/api/files/settings/get") return handleSettingsGet();
    if (path == "/api/files/settings/set-home") return handleSettingsSetHome(body);
    if (path == "/api/files/places/get") return handlePlacesGet();
    if (path == "/api/files/places/set") return handlePlacesSet(body);
    if (path == "/api/files/list") return handleList(body);
    if (path == "/api/files/mkdir") return handleMkdir(body);
    if (path == "/api/files/create") return handleCreate(body);
    if (path == "/api/files/rename") return handleRename(body);
    if (path == "/api/files/properties/get") return handlePropertiesGet(body);
    if (path == "/api/files/principals/list") return handlePrincipalsList(body);
    if (path == "/api/files/job/start") return handleJobStart(body);
    if (path == "/api/files/job/status") return handleJobStatus(body);
    if (path == "/api/files/job/cancel") return handleJobCancel(body);
    if (path == "/api/files/text/open") return handleTextOpen(body);
    if (path == "/api/files/text/read") return handleTextRead(body);
    if (path == "/api/files/text/save/start") return handleTextSaveStart(body);
    if (path == "/api/files/text/save/chunk") return handleTextSaveChunk(body);
    if (path == "/api/files/text/save/commit") return handleTextSaveCommit(body);
    if (path == "/api/files/text/save/abort") return handleTextSaveAbort(body);
    return makeApiError({"NOT_FOUND", "Unknown file API route", ENOENT}, 404);
}

ApiReply FileManagerApi::handleSettingsGet() {
    std::string stored;
    (void)kernel_module::read_string_disk_storage("file_manager_settings_v1", stored);
    std::string left = "/sdcard";
    std::string right = "/sdcard";
    auto root = makeJson(cJSON_Parse(stored.c_str()));
    if (root && cJSON_IsObject(root.get())) {
        cJSON* left_item = cJSON_GetObjectItemCaseSensitive(root.get(), "leftHome");
        cJSON* right_item = cJSON_GetObjectItemCaseSensitive(root.get(), "rightHome");
        if (cJSON_IsString(left_item) && left_item->valuestring) left = left_item->valuestring;
        if (cJSON_IsString(right_item) && right_item->valuestring) right = right_item->valuestring;
    }
    if (!m_files.isDirectory(left)) left = "/sdcard";
    if (!m_files.isDirectory(right)) right = "/sdcard";
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "leftHome", left.c_str());
    cJSON_AddStringToObject(data, "rightHome", right.c_str());
    return success(data);
}

ApiReply FileManagerApi::handleSettingsSetHome(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string pane;
    std::string path;
    if (!getString(root.get(), "pane", pane, error) || !getString(root.get(), "path", path, error)) {
        return makeApiError(error);
    }
    if (pane != "left" && pane != "right") {
        return makeApiError({"INVALID_ARGUMENT", "Pane must be 'left' or 'right'", EINVAL});
    }
    std::string normalized;
    if (!FileService::normalizeAbsolutePath(path, normalized, error)) return makeApiError(error);
    if (!m_files.isDirectory(normalized)) {
        return makeApiError({"NOT_DIRECTORY", "Home path is not an accessible directory", ENOTDIR});
    }

    std::string stored;
    (void)kernel_module::read_string_disk_storage("file_manager_settings_v1", stored);
    std::string left = "/sdcard";
    std::string right = "/sdcard";
    auto old = makeJson(cJSON_Parse(stored.c_str()));
    if (old && cJSON_IsObject(old.get())) {
        cJSON* left_item = cJSON_GetObjectItemCaseSensitive(old.get(), "leftHome");
        cJSON* right_item = cJSON_GetObjectItemCaseSensitive(old.get(), "rightHome");
        if (cJSON_IsString(left_item) && left_item->valuestring) left = left_item->valuestring;
        if (cJSON_IsString(right_item) && right_item->valuestring) right = right_item->valuestring;
    }
    if (pane == "left") left = normalized;
    else right = normalized;
    auto settings = makeJson(cJSON_CreateObject());
    cJSON_AddStringToObject(settings.get(), "leftHome", left.c_str());
    cJSON_AddStringToObject(settings.get(), "rightHome", right.c_str());
    std::string json = printJson(settings.get());
    KModErr result = kernel_module::write_string_disk_storage("file_manager_settings_v1", json.c_str());
    if (!is_ok(result)) {
        return makeApiError({"STORAGE_FAILED", "Unable to persist file manager settings: " + to_string(result), EIO});
    }
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "leftHome", left.c_str());
    cJSON_AddStringToObject(data, "rightHome", right.c_str());
    return success(data);
}

ApiReply FileManagerApi::handlePlacesGet() {
    std::vector<PlaceEntry> bookmarks;
    std::vector<PlaceEntry> recent;
    readStoredPlaces(bookmarks, recent);
    return success(placesJson(bookmarks, recent));
}

ApiReply FileManagerApi::handlePlacesSet(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);

    std::vector<PlaceEntry> bookmarks;
    std::vector<PlaceEntry> recent;
    if (!parsePlaceArray(cJSON_GetObjectItemCaseSensitive(root.get(), "bookmarks"),
                         true, true, kMaxBookmarks, bookmarks, error)
        || !parsePlaceArray(cJSON_GetObjectItemCaseSensitive(root.get(), "recent"),
                            false, true, kMaxRecent, recent, error)) {
        return makeApiError(error);
    }

    auto stored = makeJson(placesJson(bookmarks, recent));
    const std::string json = printJson(stored.get());
    const KModErr result = kernel_module::write_string_disk_storage(kPlacesStorageKey, json.c_str());
    if (!is_ok(result)) {
        return makeApiError({"STORAGE_FAILED", "Unable to persist bookmarks and recent paths: "
            + to_string(result), EIO});
    }
    return success(placesJson(bookmarks, recent));
}

ApiReply FileManagerApi::handleList(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    if (!getString(root.get(), "path", path, error)) return makeApiError(error);
    std::string normalized;
    if (!FileService::normalizeAbsolutePath(path, normalized, error)) return makeApiError(error);
    std::string items_json;
    if (!m_files.list(normalized, items_json, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "path", normalized.c_str());
    cJSON* items = cJSON_Parse(items_json.c_str());
    cJSON_AddItemToObject(data, "items", items ? items : cJSON_CreateArray());
    return success(data);
}

ApiReply FileManagerApi::handleMkdir(const std::string& body) {
    if (m_jobs.isActive() || m_text.hasActiveSave()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    uint64_t mode = 0755;
    if (!getString(root.get(), "path", path, error) || !getUint64(root.get(), "mode", mode, error, 0755)) {
        return makeApiError(error);
    }
    if (!m_files.makeDirectory(path, static_cast<uint32_t>(mode), error)) return makeApiError(error);
    return success(cJSON_CreateObject(), 201);
}

ApiReply FileManagerApi::handleCreate(const std::string& body) {
    if (m_jobs.isActive() || m_text.hasActiveSave()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    uint64_t mode = 0644;
    if (!getString(root.get(), "path", path, error)
        || !getUint64(root.get(), "mode", mode, error, 0644)) return makeApiError(error);
    if (mode > 0777) return makeApiError({"INVALID_MODE", "Create mode must be between 000 and 777", EINVAL});
    uint32_t actual_mode = 0;
    if (!m_files.createFile(path, static_cast<uint32_t>(mode), actual_mode, error)) return makeApiError(error);
    std::string normalized;
    if (!FileService::normalizeAbsolutePath(path, normalized, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "path", normalized.c_str());
    cJSON_AddStringToObject(data, "modeOctal", octalMode(actual_mode).c_str());
    return success(data, 201);
}

ApiReply FileManagerApi::handleRename(const std::string& body) {
    if (m_jobs.isActive() || m_text.hasActiveSave()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string source;
    std::string target;
    if (!getString(root.get(), "source", source, error) || !getString(root.get(), "target", target, error)) {
        return makeApiError(error);
    }
    if (!m_files.renamePath(source, target, error)) return makeApiError(error);
    return success(cJSON_CreateObject());
}

ApiReply FileManagerApi::handlePropertiesGet(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    if (!getString(root.get(), "path", path, error)) return makeApiError(error);
    FileProperties result;
    if (!m_files.getProperties(path, result, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "path", result.path.c_str());
    cJSON_AddStringToObject(data, "name", result.name.c_str());
    cJSON_AddStringToObject(data, "type", result.type.c_str());
    cJSON_AddNumberToObject(data, "size", static_cast<double>(result.size));
    cJSON_AddNumberToObject(data, "mtimeMs", static_cast<double>(result.mtime_ms));
    cJSON_AddStringToObject(data, "modeOctal", octalMode(result.mode).c_str());
    cJSON_AddStringToObject(data, "symbolic", symbolicMode(result.mode).c_str());
    cJSON_AddStringToObject(data, "uid", std::to_string(result.uid).c_str());
    cJSON_AddStringToObject(data, "ownerName", result.owner_name.c_str());
    cJSON_AddStringToObject(data, "gid", std::to_string(result.gid).c_str());
    cJSON_AddStringToObject(data, "groupName", result.group_name.c_str());
    cJSON_AddStringToObject(data, "symlinkTarget", result.symlink_target.c_str());
    cJSON_AddBoolToObject(data, "recursiveEligible", result.recursive_eligible);
    return success(data);
}

ApiReply FileManagerApi::handlePrincipalsList(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    if (!getString(root.get(), "path", path, error)) return makeApiError(error);
    std::vector<PrincipalEntry> users;
    std::vector<PrincipalEntry> groups;
    if (!m_files.listPrincipals(path, users, groups, error)) return makeApiError(error);
    auto make_list = [](const std::vector<PrincipalEntry>& values) {
        cJSON* array = cJSON_CreateArray();
        for (const auto& value : values) {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "name", value.name.c_str());
            cJSON_AddStringToObject(item, "id", std::to_string(value.id).c_str());
            cJSON_AddItemToArray(array, item);
        }
        return array;
    };
    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "users", make_list(users));
    cJSON_AddItemToObject(data, "groups", make_list(groups));
    return success(data);
}

ApiReply FileManagerApi::handleJobStart(const std::string& body) {
    if (m_text.hasActiveSave()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string op;
    std::string conflict = "skip";
    std::string destination;
    if (!getString(root.get(), "op", op, error)
        || !getString(root.get(), "conflict", conflict, error, false)
        || !getString(root.get(), "destination", destination, error, false)) return makeApiError(error);

    OperationSpec spec;
    if (op == "copy") spec.type = OperationType::Copy;
    else if (op == "move") spec.type = OperationType::Move;
    else if (op == "delete") spec.type = OperationType::Delete;
    else if (op == "extract") spec.type = OperationType::Extract;
    else if (op == "properties") spec.type = OperationType::Properties;
    else if (op == "compress") spec.type = OperationType::Compress;
    else if (op == "install_apk") spec.type = OperationType::InstallApk;
    else return makeApiError({"INVALID_ARGUMENT", "Operation must be copy, move, delete, extract, properties, compress, or install_apk", EINVAL});
    if (conflict.empty() || conflict == "skip") spec.conflict = ConflictPolicy::Skip;
    else if (conflict == "overwrite") spec.conflict = ConflictPolicy::Overwrite;
    else return makeApiError({"INVALID_ARGUMENT", "Conflict policy must be overwrite or skip", EINVAL});
    spec.destination = destination;

    cJSON* sources = cJSON_GetObjectItemCaseSensitive(root.get(), "sources");
    if (!cJSON_IsArray(sources)) return makeApiError({"INVALID_ARGUMENT", "Field 'sources' must be an array", EINVAL});
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, sources) {
        if (!cJSON_IsString(item) || !item->valuestring) {
            return makeApiError({"INVALID_ARGUMENT", "Every source path must be a string", EINVAL});
        }
        spec.sources.emplace_back(item->valuestring);
    }
    cJSON* selection = cJSON_GetObjectItemCaseSensitive(root.get(), "archiveSelection");
    if (selection) {
        if (spec.type != OperationType::Extract || !cJSON_IsObject(selection) || spec.sources.size() != 1) {
            return makeApiError({"INVALID_ARGUMENT", "Archive selection requires a single-source extract operation", EINVAL});
        }
        std::string session, base;
        if (!getString(selection, "sessionId", session, error)
            || !getString(selection, "basePath", base, error)) return makeApiError(error);
        cJSON* ids = cJSON_GetObjectItemCaseSensitive(selection, "entryIds");
        if (!cJSON_IsArray(ids) || cJSON_GetArraySize(ids) < 1 || cJSON_GetArraySize(ids) > 500) {
            return makeApiError({"INVALID_ARGUMENT", "Select between 1 and 500 archive entries", EINVAL});
        }
        std::vector<std::string> entry_ids;
        cJSON* id = nullptr;
        cJSON_ArrayForEach(id, ids) {
            if (!cJSON_IsString(id) || !id->valuestring) return makeApiError({"INVALID_ARGUMENT", "Archive entry IDs must be strings", EINVAL});
            entry_ids.emplace_back(id->valuestring);
        }
        if (!m_archives.resolveSelection(session, base, entry_ids, spec.archive_selection, error)) return makeApiError(error);
        std::string source;
        if (!FileService::normalizeAbsolutePath(spec.sources[0], source, error)) return makeApiError(error);
        if (source != spec.archive_selection.archive_path) return makeApiError({"INVALID_ARGUMENT", "Archive selection source mismatch", EINVAL});
    }
    if (spec.type == OperationType::Properties) {
        cJSON* values = cJSON_GetObjectItemCaseSensitive(root.get(), "properties");
        if (!cJSON_IsObject(values)) {
            return makeApiError({"INVALID_PROPERTIES", "Field 'properties' must be an object", EINVAL});
        }
        std::string mode;
        std::string owner;
        std::string group;
        if (!getString(values, "mode", mode, error, false)
            || !getString(values, "owner", owner, error, false)
            || !getString(values, "group", group, error, false)
            || !getBool(values, "recursiveFiles", spec.properties.recursive_files, error, false)
            || !getBool(values, "recursiveDirectories", spec.properties.recursive_directories, error, false)) {
            return makeApiError(error);
        }
        if (!mode.empty()) {
            if (!parseModeString(mode, spec.properties.mode)) {
                return makeApiError({"INVALID_MODE", "Mode must be a three or four digit octal string", EINVAL});
            }
            spec.properties.has_mode = true;
        }
        if (!owner.empty()) {
            if (!m_files.resolveUser(owner, spec.properties.uid, error)) return makeApiError(error);
            spec.properties.has_uid = true;
        }
        if (!group.empty()) {
            if (!m_files.resolveGroup(group, spec.properties.gid, error)) return makeApiError(error);
            spec.properties.has_gid = true;
        }
        if (!spec.properties.has_mode && !spec.properties.has_uid && !spec.properties.has_gid) {
            return makeApiError({"INVALID_PROPERTIES", "At least one of mode, owner, or group is required", EINVAL});
        }
    }
    std::string job_id;
    if (!m_jobs.start(spec, job_id, error)) return makeApiError(error);
    return success(jobJson(m_jobs.snapshot(job_id)), 202);
}

ApiReply FileManagerApi::handleJobStatus(const std::string& body) {
    Error error;
    std::string id;
    if (!body.empty()) {
        auto root = parseObject(body, error);
        if (!root) return makeApiError(error);
        if (!getString(root.get(), "id", id, error, false)) return makeApiError(error);
    }
    JobSnapshot value = m_jobs.snapshot(id);
    if (value.state == "not_found") return makeApiError({"JOB_NOT_FOUND", "File operation job was not found", ENOENT});
    return success(jobJson(value));
}

ApiReply FileManagerApi::handleJobCancel(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    if (!getString(root.get(), "id", id, error)) return makeApiError(error);
    if (!m_jobs.cancel(id, error)) return makeApiError(error);
    return success(jobJson(m_jobs.snapshot(id)));
}

ApiReply FileManagerApi::handleTextOpen(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    if (!getString(root.get(), "path", path, error)) return makeApiError(error);
    TextOpenResult result;
    if (!m_text.openText(path, result, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "sessionId", result.session_id.c_str());
    cJSON_AddStringToObject(data, "path", result.path.c_str());
    cJSON_AddNumberToObject(data, "size", static_cast<double>(result.size));
    cJSON_AddBoolToObject(data, "hasBom", result.has_bom);
    cJSON_AddBoolToObject(data, "readOnly", result.read_only);
    cJSON_AddItemToObject(data, "version", versionJson(result.version));
    return success(data);
}

ApiReply FileManagerApi::handleTextRead(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    uint64_t offset = 0;
    uint64_t limit = kMaxTransferChunkBytes;
    if (!getString(root.get(), "sessionId", id, error)
        || !getUint64(root.get(), "offset", offset, error)
        || !getUint64(root.get(), "limit", limit, error, kMaxTransferChunkBytes)) return makeApiError(error);
    TextReadResult result;
    if (!m_text.readChunk(id, offset, static_cast<size_t>(limit), result, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "base64", result.base64_data.c_str());
    cJSON_AddNumberToObject(data, "offset", static_cast<double>(result.offset));
    cJSON_AddNumberToObject(data, "nextOffset", static_cast<double>(result.next_offset));
    cJSON_AddBoolToObject(data, "eof", result.eof);
    return success(data);
}

ApiReply FileManagerApi::handleTextSaveStart(const std::string& body) {
    if (m_jobs.isActive()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    uint64_t size = 0;
    bool force = false;
    FileVersion version;
    if (!getString(root.get(), "path", path, error)
        || !getUint64(root.get(), "size", size, error)
        || !getBool(root.get(), "force", force, error, false)
        || !parseVersion(root.get(), version, error)) return makeApiError(error);
    std::string id;
    if (!m_text.startSave(path, version, size, force, id, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "saveId", id.c_str());
    cJSON_AddNumberToObject(data, "chunkSize", static_cast<double>(kMaxTransferChunkBytes));
    return success(data, 201);
}

ApiReply FileManagerApi::handleTextSaveChunk(const std::string& body) {
    if (m_jobs.isActive()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    std::string base64;
    uint64_t offset = 0;
    if (!getString(root.get(), "saveId", id, error)
        || !getString(root.get(), "base64", base64, error)
        || !getUint64(root.get(), "offset", offset, error)) return makeApiError(error);
    uint64_t received = 0;
    if (!m_text.writeChunk(id, offset, base64, received, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "received", static_cast<double>(received));
    return success(data);
}

ApiReply FileManagerApi::handleTextSaveCommit(const std::string& body) {
    if (m_jobs.isActive()) return busyReply();
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    bool force = false;
    if (!getString(root.get(), "saveId", id, error) || !getBool(root.get(), "force", force, error, false)) {
        return makeApiError(error);
    }
    FileVersion version;
    if (!m_text.commitSave(id, force, version, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "version", versionJson(version));
    return success(data);
}

ApiReply FileManagerApi::handleTextSaveAbort(const std::string& body) {
    Error error;
    std::string id;
    if (!body.empty()) {
        auto root = parseObject(body, error);
        if (!root) return makeApiError(error);
        if (!getString(root.get(), "saveId", id, error, false)) return makeApiError(error);
    }
    if (!m_text.abortSave(id, error)) return makeApiError(error);
    return success(cJSON_CreateObject());
}

bool FileManagerApi::isJobActive() const {
    return m_jobs.isActive() || m_archives.isActive();
}

void FileManagerApi::shutdown() {
    std::lock_guard<std::mutex> write_lk(m_write_mu);
    m_jobs.shutdown();
    m_text.shutdown();
    m_archives.shutdown();
    m_images.shutdown();
}

void FileManagerApi::requestStop() {
    m_stop_requested.store(true, std::memory_order_release);
    m_jobs.requestStop();
    m_archives.requestStop();
}

ApiReply FileManagerApi::handleImageOpen(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string path;
    if (!getString(root.get(), "path", path, error)) return makeApiError(error);
    ImageOpenResult result;
    if (!m_images.openImage(path, result, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "sessionId", result.session_id.c_str());
    cJSON_AddStringToObject(data, "path", result.path.c_str());
    cJSON_AddStringToObject(data, "mime", result.mime.c_str());
    cJSON_AddNumberToObject(data, "size", static_cast<double>(result.size));
    cJSON_AddNumberToObject(data, "width", result.width);
    cJSON_AddNumberToObject(data, "height", result.height);
    cJSON_AddItemToObject(data, "version", versionJson(result.version));
    return success(data);
}

ApiReply FileManagerApi::handleImageRead(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    uint64_t offset = 0, limit = kMaxTransferChunkBytes;
    if (!getString(root.get(), "sessionId", id, error)
        || !getUint64(root.get(), "offset", offset, error)
        || !getUint64(root.get(), "limit", limit, error, kMaxTransferChunkBytes)) return makeApiError(error);
    TextReadResult result;
    if (!m_images.readChunk(id, offset, static_cast<size_t>(limit), result, error)) return makeApiError(error);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "base64", result.base64_data.c_str());
    cJSON_AddNumberToObject(data, "offset", static_cast<double>(result.offset));
    cJSON_AddNumberToObject(data, "nextOffset", static_cast<double>(result.next_offset));
    cJSON_AddBoolToObject(data, "eof", result.eof);
    return success(data);
}

ApiReply FileManagerApi::handleImageClose(const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    std::string id;
    if (!getString(root.get(), "sessionId", id, error)) return makeApiError(error);
    m_images.close(id);
    return success();
}

ApiReply FileManagerApi::handleArchive(const std::string& path, const std::string& body) {
    Error error;
    auto root = parseObject(body, error);
    if (!root) return makeApiError(error);
    const std::string action = path.substr(std::string("/api/files/archive/").size());
    std::string id;
    if (action != "open" && !getString(root.get(), "sessionId", id, error)) return makeApiError(error);
    if (action == "close") {
        if (!m_archives.close(id, error)) return makeApiError(error);
        return success();
    }
    if (action == "list") {
        std::string inner;
        uint64_t offset = 0, limit = 500;
        if (!getString(root.get(), "innerPath", inner, error, false)
            || !getUint64(root.get(), "offset", offset, error, 0)
            || !getUint64(root.get(), "limit", limit, error, 500)) return makeApiError(error);
        ArchiveBrowserList result;
        if (!m_archives.list(id, inner, offset, static_cast<size_t>(limit), result, error)) return makeApiError(error);
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "sessionId", result.session_id.c_str());
        cJSON_AddStringToObject(data, "innerPath", result.inner_path.c_str());
        cJSON_AddNumberToObject(data, "offset", static_cast<double>(result.offset));
        cJSON_AddNumberToObject(data, "nextOffset", static_cast<double>(result.next_offset));
        cJSON_AddNumberToObject(data, "total", static_cast<double>(result.total));
        cJSON_AddBoolToObject(data, "eof", result.eof);
        cJSON* items = cJSON_AddArrayToObject(data, "items");
        for (const auto& entry : result.entries) {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "id", entry.id.c_str());
            cJSON_AddStringToObject(item, "name", entry.name.c_str());
            cJSON_AddStringToObject(item, "path", entry.path.c_str());
            cJSON_AddStringToObject(item, "type", entry.type.c_str());
            cJSON_AddNumberToObject(item, "size", static_cast<double>(entry.size));
            cJSON_AddNumberToObject(item, "mtimeMs", static_cast<double>(entry.mtime_ms));
            cJSON_AddNumberToObject(item, "duplicateIndex", static_cast<double>(entry.duplicate_index));
            cJSON_AddBoolToObject(item, "isImplicit", entry.is_implicit);
            cJSON_AddBoolToObject(item, "selectable", entry.selectable);
            cJSON_AddItemToArray(items, item);
        }
        return success(data);
    }
    ArchiveBrowserStatus result;
    if (action == "open") {
        std::string source;
        if (!getString(root.get(), "path", source, error)) return makeApiError(error);
        if (!m_archives.open(source, result, error)) return makeApiError(error);
    } else if (action == "status") {
        if (!m_archives.status(id, result, error)) return makeApiError(error);
    } else return makeApiError({"NOT_FOUND", "Unknown archive route", ENOENT}, 404);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "sessionId", result.session_id.c_str());
    cJSON_AddStringToObject(data, "path", result.archive_path.c_str());
    cJSON_AddStringToObject(data, "state", result.state.c_str());
    cJSON_AddNumberToObject(data, "scannedEntries", static_cast<double>(result.scanned_entries));
    cJSON_AddNumberToObject(data, "totalEntries", static_cast<double>(result.total_entries));
    cJSON_AddNumberToObject(data, "totalNodes", static_cast<double>(result.total_nodes));
    cJSON_AddItemToObject(data, "version", versionJson(result.version));
    cJSON* failure = cJSON_AddObjectToObject(data, "error");
    cJSON_AddStringToObject(failure, "code", result.error.code.c_str());
    cJSON_AddStringToObject(failure, "message", result.error.message.c_str());
    return success(data, action == "open" ? 202 : 200);
}

} // namespace file_manager
