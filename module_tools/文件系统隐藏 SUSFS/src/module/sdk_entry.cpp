// SPDX-License-Identifier: GPL-2.0-only
#include "kernel_module_kit_umbrella.h"
#include "identity.h"
#include "../management/embedded.hpp"
#include "vendor/file_manager/file_broker.h"
#include "vendor/file_manager/app_metadata_service.h"
#include "webui_access_policy.h"
#include "webui_lifecycle.h"
#include "../management/common.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <string>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool acquire_root(const char* key) {
    if (!key || !*key) return false;
    return !is_failed(skroot_env::get_root(key));
}
std::string failure(const char* code, const std::string& message) {
    return "{\"ok\":false,\"code\":" + susfs::management::quote(code) +
        ",\"message\":" + susfs::management::quote(message) +
        ",\"error\":" + susfs::management::quote(message) + ",\"errno\":0,\"data\":null}";
}
bool loopback_request(mg_connection* connection) {
    const auto* info = mg_get_request_info(connection);
    return info && info->remote_addr && (webui_access::isLoopbackAddress(info->remote_addr) ||
        webui_access::isLoopbackDestination(info->server_port, info->remote_port, info->remote_addr));
}
bool loopback_host(std::string value) {
    if (value.empty()) return false;
    std::string host, port; bool has_port = false;
    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string::npos) return false;
        host = value.substr(1, close - 1);
        if (close + 1 < value.size()) {
            if (value[close + 1] != ':') return false;
            has_port = true; port = value.substr(close + 2);
        }
    } else {
        const auto colon = value.find(':');
        if (colon != std::string::npos && colon == value.rfind(':')) {
            host = value.substr(0, colon); has_port = true; port = value.substr(colon + 1);
        } else host = value;
    }
    if (has_port && (port.empty() || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return std::isdigit(c); }) || std::strtoul(port.c_str(), nullptr, 10) > 65535)) return false;
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return host == "localhost" || webui_access::isLoopbackAddress(host);
}
bool allowed_origin(mg_connection* connection) {
    const char* host = mg_get_header(connection, "Host");
    if (!host || !loopback_host(host)) return false;
    const char* origin = mg_get_header(connection, "Origin");
    return !origin || !*origin || std::string(origin) == std::string("http://") + host ||
        std::string(origin) == std::string("https://") + host;
}

class SusfsWeb final : public kernel_module::WebUIHttpHandler {
public:
    ~SusfsWeb() override {
        halt_.store(true); wake_.notify_all();
        if(coordinator_.joinable())coordinator_.join();
    }
    void onPrepareCreate(const char* root_key, const char* private_directory,
                         uint32_t) override {
        directory_ = private_directory ? private_directory : "";
        session_ = file_manager::randomHex(32);
        if (!acquire_root(root_key)) { startup_error_ = "root_unavailable"; return; }
        if (directory_.empty()) {
            startup_error_ = "private_directory_missing";
            return;
        }
        std::string error;
        if (!susfs::embedded::start(directory_, error))
            startup_error_ = error.empty() ? "service_start_failed" : error;
        // The broker child registers and owns its own precise manager FD.
        (void)broker_.start("susfs4skp");
        metadata_.configure(directory_ + "/app-metadata.dex");
        lifecycle_.configure(susfs::embedded::no_background(directory_));
    }
    void onServerCreated(CivetServer* server) override {
        server_=server;
        coordinator_=std::thread([this]{
            std::unique_lock<std::mutex> lock(wake_mutex_);
            while(!halt_.load()&&!lifecycle_.closing()){
                wake_.wait_for(lock,std::chrono::seconds(1));
                if(lifecycle_.expired())lifecycle_.close();
            }
            if(halt_.load())return;
            lock.unlock();
            // A CivetWeb worker must never wait for its own close. This
            // coordinator drains HTTP callbacks before stopping owned children.
            if(server_)server_->close();
            broker_.shutdown();
            std::string error;
            (void)susfs::embedded::stop(directory_,error);
            _exit(0);
        });
    }
    ServerExitAction onBeforeServerExit() override {
        if(lifecycle_.enabled()||lifecycle_.closing()){
            lifecycle_.close();wake_.notify_all();
            return ServerExitAction::KeepRunning;
        }
        halt_.store(true);wake_.notify_all();
        return ServerExitAction::Exit;
    }

    bool handleGet(CivetServer*, mg_connection* connection,
                   const std::string& path, const std::string&) override {
        return dispatch(connection, path, "", false);
    }

    bool handlePost(CivetServer*, mg_connection* connection,
                    const std::string& path, const std::string& body) override {
        return dispatch(connection, path, body, true);
    }
    bool handlePost(CivetServer* server,mg_connection* connection) override {
        const auto path=kernel_module::webui::get_request_path(connection);
        std::string body;
        const auto result=kernel_module::webui::read_request_body(connection,body,
            path=="/api/susfs/config-save"?524288:256*1024);
        if(result==kernel_module::webui::BodyReadStatus::TOO_LARGE)
            return kernel_module::webui::send_json(connection,413,failure("PAYLOAD_TOO_LARGE","Configuration is too large"));
        if(result!=kernel_module::webui::BodyReadStatus::OK)
            return kernel_module::webui::send_json(connection,400,failure("INVALID_BODY","Incomplete request body"));
        return handlePost(server,connection,path,body);
    }

private:
    static const char* route(const std::string& path, bool post) {
        // The current WebUI client posts JSON for every API.  Accepting GET
        // as well keeps the public routes useful to diagnostics tools without
        // creating a second protocol.
        if (path == "/api/susfs/status") return "/status";
        if (path == "/api/susfs/config-get") return "/config";
        if (path == "/api/susfs/apps") return "/apps";
        if (path == "/api/susfs/objects-query" && post) return "/objects/query";
        if (path == "/api/susfs/kstat-sample" && post) return "/kstat/sample";
        if (path == "/api/susfs/config-save" && post) return "/config/save";
        if (path == "/api/susfs/config-import" && post) return "/config/import";
        if (path == "/api/susfs/config-export" && post) return "/config/export";
        if (path == "/api/susfs/apply" && post) return "/apply";
        return nullptr;
    }
    bool dispatch(mg_connection* connection, const std::string& path,
                  const std::string& body, bool post) {
        if (!loopback_request(connection)) return kernel_module::webui::send_json(connection, 403, failure("REMOTE_ACCESS_DENIED", "WebUI is restricted to this device"));
        if (!allowed_origin(connection)) return kernel_module::webui::send_json(connection, 403, failure("ORIGIN_DENIED", "Request origin does not match this WebUI"));
        if (post && path == "/api/session") {
            if (session_.empty() || !startup_error_.empty()) return kernel_module::webui::send_json(connection, 503, failure("SERVICE_UNAVAILABLE", startup_error_));
            return kernel_module::webui::send_json(connection, 200,
                "{\"ok\":true,\"code\":\"OK\",\"message\":\"\",\"errno\":0,\"data\":{\"token\":" + susfs::management::quote(session_) + "}}");
        }
        const bool api = path.rfind("/api/", 0) == 0;
        if (api || post) {
            const char* token = mg_get_header(connection, "X-SKRoot-Session");
            if (!token || session_.empty() || session_ != token) return kernel_module::webui::send_json(connection, 401, failure("INVALID_SESSION", "Missing or invalid WebUI session token"));
        }
        if(lifecycle_.closing())return kernel_module::webui::send_json(connection,410,failure("WEBUI_CLOSED","WebUI has closed; reopen it from SKP"));
        if(post&&path=="/api/susfs/webui/exit"){
            lifecycle_.close();
            const bool sent=kernel_module::webui::send_json(connection,200,"{\"ok\":true,\"data\":{\"closed\":true}}");
            wake_.notify_all();return sent;
        }
        if(post&&path=="/api/susfs/webui/ping"){
            lifecycle_.touch();
            (void)susfs::embedded::request(directory_,"/service/ping","");
            return kernel_module::webui::send_json(connection,200,
                std::string("{\"ok\":true,\"data\":{\"no_background\":")+(lifecycle_.enabled()?"true":"false")+"}}");
        }
        if (path.rfind("/api/files/", 0) == 0) {
            const auto reply = broker_.handle(path, body);
            return kernel_module::webui::send_json(connection, reply.status, reply.body);
        }
        if (path == "/api/apps/metadata" && post) {
            const auto reply = metadata_.handle(body);
            return kernel_module::webui::send_json(connection, reply.status, reply.body);
        }
        const char* target = route(path, post);
        if (!target) {
            // Returning false lets the SDK static WebUI handler serve index,
            // scripts, styles and vendor assets from the module package.
            if (!post && path.rfind("/api/", 0) != 0) return false;
            return kernel_module::webui::send_json(connection, 404,
                "{\"ok\":false,\"error\":\"unknown_route\"}");
        }
        if (!startup_error_.empty()) {
            return kernel_module::webui::send_json(connection, 503,
                "{\"ok\":false,\"error\":\"service_unavailable\"}");
        }
        const auto reply = susfs::embedded::request(directory_, target, body);
        if(path=="/api/susfs/config-save"&&reply.status==200)
            lifecycle_.configure(susfs::embedded::no_background(directory_));
        return kernel_module::webui::send_json(connection, reply.status, reply.body);
    }
    std::string directory_;
    std::string startup_error_;
    std::string session_;
    file_manager::FileBroker broker_;
    app_metadata::Service metadata_;
    susfs::WebuiLifecycle lifecycle_;
    std::atomic<bool> halt_{false};
    CivetServer* server_=nullptr;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::thread coordinator_;
};
}

int skroot_module_main(const char* root_key, const char* private_directory) {
    if (!acquire_root(root_key)) return 1;
    const std::string directory = private_directory ? private_directory : "";
    if (directory.empty()) return 2;
    std::string error;
    return susfs::embedded::start(directory, error) ? 0 : 1;
}

std::string module_on_install(const char* root_key, const char* private_directory) {
    if (!acquire_root(root_key)) return "Cannot acquire module root context";
    const std::string directory = private_directory ? private_directory : "";
    if (directory.empty()) return "Missing module private directory";
    // stop() checks the exact PID start stamp and signals through pidfd. An
    // absent service is harmless; never kill by a stale PID or a module name.
    std::string error;
    return susfs::embedded::stop(directory, error) ? "" : "Cannot stop existing private service: " + error;
}
void module_on_uninstall(const char* root_key, const char* private_directory) {
    if (!acquire_root(root_key) || !private_directory || !*private_directory) return;
    std::string error;
    // Do not rmmod here: the loader may have loaded a shared/built-in LKM and
    // the SDK owns no safe proof that this module is its sole reference. The
    // normal upstream lifecycle keeps the KO until reboot or an explicit,
    // independently verified loader action.
    (void)susfs::embedded::stop(private_directory, error);
}

SKROOT_MODULE_NAME("文件系统隐藏 SUSFS")
SKROOT_MODULE_VERSION(SUSFS_STANDALONE_VERSION)
SKROOT_MODULE_DESC("提供文件隐藏、状态伪装、重定向，以及内核版本伪装、启动信息修改、内核模块隐藏、AVC 日志伪装等 SUSFS 功能。在原 SUSFS 项目基础上优化，支持规则独立作用域调整、按域豁免，并提供可视化 WebUI 配置。")
SKROOT_MODULE_AUTHOR("斓梦语、SUSFS4KSU-LKM")
SKROOT_MODULE_ID32(SUSFS_STANDALONE_MODULE_ID)
SKROOT_MODULE_WEB_UI(SusfsWeb)
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
