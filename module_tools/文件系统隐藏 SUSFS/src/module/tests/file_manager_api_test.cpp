#include "../vendor/file_manager/file_manager_api.h"
#include "../vendor/file_manager/cJSON.h"
#include "module_base_disk_storage.h"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <thread>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace kernel_module {
namespace {
std::map<std::string, std::string> storage;
}

KModErr write_string_disk_storage(const char* key, const char* value) {
    storage[key ? key : ""] = value ? value : "";
    return KModErr::OK;
}

KModErr read_string_disk_storage(const char* key, std::string& out) {
    auto it = storage.find(key ? key : "");
    if (it == storage.end()) {
        out.clear();
        return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    }
    out = it->second;
    return KModErr::OK;
}
} // namespace kernel_module

namespace {

std::string dataString(const file_manager::ApiReply& reply, const char* name) {
    cJSON* root = cJSON_Parse(reply.body.c_str());
    assert(root);
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* value = cJSON_GetObjectItemCaseSensitive(data, name);
    assert(cJSON_IsString(value));
    std::string result = value->valuestring;
    cJSON_Delete(root);
    return result;
}

uint64_t dataNumber(const file_manager::ApiReply& reply, const char* name) {
    cJSON* root = cJSON_Parse(reply.body.c_str());
    assert(root && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* value = cJSON_GetObjectItemCaseSensitive(data, name);
    assert(cJSON_IsNumber(value) && value->valuedouble >= 0);
    const uint64_t result = static_cast<uint64_t>(value->valuedouble);
    cJSON_Delete(root);
    return result;
}

bool dataBool(const file_manager::ApiReply& reply, const char* name) {
    cJSON* root = cJSON_Parse(reply.body.c_str());
    assert(root && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* value = cJSON_GetObjectItemCaseSensitive(data, name);
    assert(cJSON_IsBool(value));
    const bool result = cJSON_IsTrue(value);
    cJSON_Delete(root);
    return result;
}

std::string dataVersion(const file_manager::ApiReply& reply, const std::string& expected_size) {
    cJSON* root = cJSON_Parse(reply.body.c_str());
    assert(root && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* version = cJSON_GetObjectItemCaseSensitive(data, "version");
    cJSON* size = cJSON_GetObjectItemCaseSensitive(version, "size");
    assert(cJSON_IsString(size) && size->valuestring == expected_size);
    char* serialized = cJSON_PrintUnformatted(version);
    assert(serialized);
    const std::string result(serialized);
    cJSON_free(serialized);
    cJSON_Delete(root);
    return result;
}

void expectErrorCode(const file_manager::ApiReply& reply, const std::string& expected_code) {
    cJSON* root = cJSON_Parse(reply.body.c_str());
    assert(root && cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    cJSON* code = cJSON_GetObjectItemCaseSensitive(root, "code");
    assert(cJSON_IsString(code) && code->valuestring == expected_code);
    cJSON_Delete(root);
}

} // namespace

int main() {
    char temp_template[] = "/tmp/skroot-api-test-XXXXXX";
    char* raw = ::mkdtemp(temp_template);
    assert(raw);
    fs::path root(raw);
    fs::create_directories(root / "left");
    fs::create_directories(root / "right");
    std::ofstream(root / "left/test.txt") << "hello\n";

    file_manager::FileManagerApi api;
    api.configure("");

    auto settings = api.handle("/api/files/settings/get", "{}");
    assert(settings.status == 200);

    std::string set_home_body = std::string("{\"pane\":\"left\",\"path\":\"") + (root / "left").string() + "\"}";
    auto set_home = api.handle("/api/files/settings/set-home", set_home_body);
    assert(set_home.status == 200);
    assert(dataString(set_home, "leftHome") == (root / "left").string());

    std::string places_body = std::string("{\"bookmarks\":[{\"path\":\"")
        + (root / "left").string() + "\",\"note\":\"工作目录\"}],\"recent\":[";
    for (int index = 0; index < 24; ++index) {
        if (index) places_body += ",";
        places_body += std::string("{\"path\":\"") + (root / ("recent-" + std::to_string(index))).string() + "\"}";
    }
    places_body += "]}";
    auto set_places = api.handle("/api/files/places/set", places_body);
    assert(set_places.status == 200);
    assert(set_places.body.find("工作目录") != std::string::npos);
    auto get_places = api.handle("/api/files/places/get", "{}");
    assert(get_places.status == 200);
    cJSON* places_json = cJSON_Parse(get_places.body.c_str());
    assert(places_json);
    cJSON* places_data = cJSON_GetObjectItemCaseSensitive(places_json, "data");
    assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(places_data, "bookmarks")) == 1);
    assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(places_data, "recent")) == 20);
    cJSON_Delete(places_json);
    assert(api.handle("/api/files/places/set", "{\"bookmarks\":{},\"recent\":[]}").status == 400);

    std::string list_body = std::string("{\"path\":\"") + (root / "left").string() + "\"}";
    auto list = api.handle("/api/files/list", list_body);
    assert(list.status == 200);
    assert(list.body.find("test.txt") != std::string::npos);

    std::string mkdir_body = std::string("{\"path\":\"") + (root / "left/new-dir").string() + "\",\"mode\":493}";
    auto mkdir = api.handle("/api/files/mkdir", mkdir_body);
    assert(mkdir.status == 201);
    assert(fs::is_directory(root / "left/new-dir"));

    std::string create_body = std::string("{\"path\":\"") + (root / "left/blank.txt").string()
        + "\",\"mode\":420}";
    auto created = api.handle("/api/files/create", create_body);
    assert(created.status == 201);
    assert(fs::exists(root / "left/blank.txt") && fs::file_size(root / "left/blank.txt") == 0);
    auto create_conflict = api.handle("/api/files/create", create_body);
    assert(create_conflict.status == 409);
    std::string invalid_create_body = std::string("{\"path\":\"") + (root / "left/bad.txt").string()
        + "\",\"mode\":4096}";
    assert(api.handle("/api/files/create", invalid_create_body).status == 400);

    std::string properties_body = std::string("{\"path\":\"") + (root / "left/blank.txt").string() + "\"}";
    auto properties = api.handle("/api/files/properties/get", properties_body);
    assert(properties.status == 200);
    assert(properties.body.find("modeOctal") != std::string::npos);
    auto principals = api.handle("/api/files/principals/list", properties_body);
    assert(principals.status == 200);
    assert(principals.body.find("\"users\"") != std::string::npos);

    std::string property_job_body = std::string("{\"op\":\"properties\",\"sources\":[\"")
        + (root / "left/blank.txt").string()
        + "\"],\"properties\":{\"mode\":\"0600\",\"recursiveFiles\":false,\"recursiveDirectories\":false}}";
    auto property_job = api.handle("/api/files/job/start", property_job_body);
    assert(property_job.status == 202);
    const std::string property_job_id = dataString(property_job, "id");
    for (int i = 0; i < 500; ++i) {
        auto status = api.handle("/api/files/job/status", std::string("{\"id\":\"") + property_job_id + "\"}");
        const std::string state = dataString(status, "state");
        if (state == "completed") break;
        assert(state == "scanning" || state == "running" || state == "cancelling");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    struct stat property_stat {};
    assert(::lstat((root / "left/blank.txt").c_str(), &property_stat) == 0);
    assert((property_stat.st_mode & 07777) == 0600);
    std::string bad_property_job = std::string("{\"op\":\"properties\",\"sources\":[\"")
        + (root / "left/blank.txt").string()
        + "\"],\"properties\":{\"owner\":\"skroot-user-that-does-not-exist\"}}";
    assert(api.handle("/api/files/job/start", bad_property_job).status == 400);

    std::string compress_body = std::string("{\"op\":\"compress\",\"sources\":[\"")
        + (root / "left/blank.txt").string() + "\"],\"destination\":\""
        + (root / "right").string() + "\"}";
    auto compress_job = api.handle("/api/files/job/start", compress_body);
    assert(compress_job.status == 202);
    const std::string compress_id = dataString(compress_job, "id");
    bool compress_done = false;
    for (int i = 0; i < 500; ++i) {
        auto status = api.handle("/api/files/job/status", std::string("{\"id\":\"") + compress_id + "\"}");
        const std::string state = dataString(status, "state");
        if (state == "completed") {
            assert(dataString(status, "outputPath") == (root / "right/blank.txt.zip").string());
            compress_done = true;
            break;
        }
        assert(state == "scanning" || state == "running" || state == "cancelling");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    assert(compress_done && fs::exists(root / "right/blank.txt.zip"));

    const std::string archive_path = (root / "right/blank.txt.zip").string();
    auto archive_open = api.handle("/api/files/archive/open", "{\"path\":\"" + archive_path + "\"}");
    assert(archive_open.status == 202);
    const std::string archive_id = dataString(archive_open, "sessionId");
    const std::string archive_session = "{\"sessionId\":\"" + archive_id + "\"}";
    bool archive_ready = false;
    for (int i = 0; i < 500; ++i) {
        const auto status = api.handle("/api/files/archive/status", archive_session);
        const auto state = dataString(status, "state");
        if (state == "ready") { archive_ready = true; break; }
        assert(state == "queued" || state == "scanning");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    assert(archive_ready);
    auto listing = api.handle("/api/files/archive/list", archive_session);
    assert(listing.status == 200);
    cJSON* archive_json = cJSON_Parse(listing.body.c_str());
    cJSON* archive_items = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(archive_json, "data"), "items");
    assert(cJSON_GetArraySize(archive_items) == 1);
    const std::string entry_id = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(archive_items, 0), "id")->valuestring;
    cJSON_Delete(archive_json);
    fs::create_directories(root / "selected");
    const std::string selection = "{\"sessionId\":\"" + archive_id + "\",\"basePath\":\"\",\"entryIds\":[\"" + entry_id + "\"]}";
    const std::string extract_body = "{\"op\":\"extract\",\"sources\":[\"" + archive_path +
        "\"],\"destination\":\"" + (root / "selected").string() + "\",\"archiveSelection\":" + selection + "}";
    assert(api.handle("/api/files/job/start", "{\"op\":\"copy\",\"sources\":[\"" + archive_path +
        "\"],\"archiveSelection\":" + selection + "}").status == 400);
    auto selected_job = api.handle("/api/files/job/start", extract_body);
    assert(selected_job.status == 202);
    const auto selected_id = dataString(selected_job, "id");
    assert(api.handle("/api/files/archive/close", archive_session).status == 200);
    assert(api.handle("/api/files/archive/close", archive_session).status == 200);
    assert(api.handle("/api/files/archive/list", archive_session).status == 404);
    bool selected_done = false;
    for (int i = 0; i < 500; ++i) {
        const auto status = api.handle("/api/files/job/status", "{\"id\":\"" + selected_id + "\"}");
        const auto state = dataString(status, "state");
        if (state == "completed") { selected_done = true; break; }
        assert(state == "scanning" || state == "running");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    assert(selected_done && fs::exists(root / "selected/blank.txt"));

    std::vector<uint8_t> png;
    assert(file_manager::TextTransferService::decodeBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==", png));
    const auto image_path = root / "left/picture.png";
    { std::ofstream image(image_path, std::ios::binary); image.write(reinterpret_cast<const char*>(png.data()), png.size()); }
    auto image_open = api.handle("/api/files/image/open", "{\"path\":\"" + image_path.string() + "\"}");
    assert(image_open.status == 200 && dataString(image_open, "mime") == "image/png");
    const auto image_id = dataString(image_open, "sessionId");
    const auto image_session = "{\"sessionId\":\"" + image_id + "\"}";
    assert(api.handle("/api/files/image/read", image_session).status == 200);
    assert(api.handle("/api/files/image/close", image_session).status == 200);
    assert(api.handle("/api/files/image/close", image_session).status == 200);
    assert(api.handle("/api/files/image/read", image_session).status == 404);

    std::string invalid_apk_body = std::string("{\"op\":\"install_apk\",\"sources\":[\"")
        + (root / "left/blank.txt").string() + "\"]}";
    auto invalid_apk = api.handle("/api/files/job/start", invalid_apk_body);
    assert(invalid_apk.status == 400);
    assert(invalid_apk.body.find("INVALID_APK") != std::string::npos);

    std::string rename_body = std::string("{\"source\":\"") + (root / "left/test.txt").string()
        + "\",\"target\":\"" + (root / "left/renamed.txt").string() + "\"}";
    auto renamed = api.handle("/api/files/rename", rename_body);
    assert(renamed.status == 200);
    assert(fs::exists(root / "left/renamed.txt"));

    std::string open_body = std::string("{\"path\":\"") + (root / "left/renamed.txt").string() + "\"}";
    auto opened = api.handle("/api/files/text/open", open_body);
    assert(opened.status == 200);
    assert(opened.body.find("sessionId") != std::string::npos);
    assert(!dataBool(opened, "readOnly"));
    assert(dataNumber(opened, "size") == 6);
    (void)dataVersion(opened, "6");

    const std::string blank_path = (root / "left/blank.txt").string();
    const auto empty_opened = api.handle("/api/files/text/open", "{\"path\":\"" + blank_path + "\"}");
    assert(empty_opened.status == 200);
    assert(!dataBool(empty_opened, "readOnly") && dataNumber(empty_opened, "size") == 0);
    const std::string empty_version = dataVersion(empty_opened, "0");
    const auto empty_read = api.handle("/api/files/text/read", "{\"sessionId\":\""
        + dataString(empty_opened, "sessionId") + "\",\"offset\":0,\"limit\":1}");
    assert(empty_read.status == 200 && dataBool(empty_read, "eof"));
    assert(dataString(empty_read, "base64").empty() && dataNumber(empty_read, "nextOffset") == 0);

    // Exercise real host procfs metadata through the public JSON API.
    if (::access("/proc/sys/kernel/tainted", R_OK) == 0) {
        const auto proc_opened = api.handle("/api/files/text/open", "{\"path\":\"/proc/sys/kernel/tainted\"}");
        assert(proc_opened.status == 200 && dataBool(proc_opened, "readOnly"));
        const uint64_t proc_size = dataNumber(proc_opened, "size");
        assert(proc_size > 0);
        const std::string proc_version = dataVersion(proc_opened, "0");
        const std::string proc_id = dataString(proc_opened, "sessionId");
        std::string proc_content;
        uint64_t offset = 0;
        while (true) {
            const auto chunk = api.handle("/api/files/text/read", "{\"sessionId\":\"" + proc_id
                + "\",\"offset\":" + std::to_string(offset) + ",\"limit\":1}");
            assert(chunk.status == 200 && dataNumber(chunk, "offset") == offset);
            std::vector<uint8_t> bytes;
            assert(file_manager::TextTransferService::decodeBase64(dataString(chunk, "base64"), bytes));
            const uint64_t next_offset = dataNumber(chunk, "nextOffset");
            assert(next_offset == offset + bytes.size() && next_offset <= proc_size);
            proc_content.append(bytes.begin(), bytes.end());
            if (dataBool(chunk, "eof")) break;
            assert(!bytes.empty());
            offset = next_offset;
        }
        assert(proc_content.size() == proc_size && proc_content.back() == '\n');
        assert(proc_content.find_first_not_of("0123456789\n") == std::string::npos);
        for (const char* force : {"false", "true"}) {
            const auto rejected = api.handle("/api/files/text/save/start",
                "{\"path\":\"/proc/sys/kernel/tainted\",\"size\":" + std::to_string(proc_size)
                + ",\"force\":" + force + ",\"version\":" + proc_version + "}");
            assert(rejected.status == 403);
            expectErrorCode(rejected, "READ_ONLY_FILE");
        }
    }

    // A refused virtual-file save must not reserve the one active save session.
    const auto empty_save = api.handle("/api/files/text/save/start", "{\"path\":\""
        + blank_path + "\",\"size\":0,\"force\":false,\"version\":" + empty_version + "}");
    assert(empty_save.status == 201);
    assert(api.handle("/api/files/text/save/abort", "{\"saveId\":\""
        + dataString(empty_save, "saveId") + "\"}").status == 200);

    std::ofstream(root / "left/invalid.txt", std::ios::binary) << std::string("\xff\xfe", 2);
    std::string invalid_open_body = std::string("{\"path\":\"") + (root / "left/invalid.txt").string() + "\"}";
    auto invalid_open = api.handle("/api/files/text/open", invalid_open_body);
    assert(invalid_open.status == 422);
    assert(invalid_open.body.find("INVALID_UTF8") != std::string::npos);
    assert(api.handle("/api/files/image/open", invalid_open_body).status == 422);

    std::string invalid_bool_body = std::string("{\"path\":\"") + (root / "left/renamed.txt").string()
        + "\",\"size\":0,\"force\":\"no\"}";
    auto invalid_bool = api.handle("/api/files/text/save/start", invalid_bool_body);
    assert(invalid_bool.status == 400);
    assert(invalid_bool.body.find("INVALID_ARGUMENT") != std::string::npos);

    std::string huge_mode_body = std::string("{\"path\":\"") + (root / "left/huge-mode").string()
        + "\",\"mode\":18446744073709551616}";
    auto huge_mode = api.handle("/api/files/mkdir", huge_mode_body);
    assert(huge_mode.status == 400);

    auto invalid = api.handle("/api/files/not-real", "{}");
    assert(invalid.status == 404);
    assert(invalid.body.find("NOT_FOUND") != std::string::npos);

    api.shutdown();
    fs::remove_all(root);
    return 0;
}
