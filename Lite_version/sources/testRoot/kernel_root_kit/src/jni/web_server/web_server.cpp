#include <netinet/in.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <atomic>
#include <set>
#include <mutex>
#include <filesystem>
#include <cmath>
#include <limits>

#include "web_server.h"
#include "web_server_inline.h"
#include "civetweb-1.16/include/CivetServer.h"
#include "index_html_gz_data.h"
#include "rootkit_umbrella.h"
#include "src/jni/common/android_open_url.h"
#include "json_helper.h"

#define MAX_HEARTBEAT_TIME_SEC 20
constexpr const char* recommend_files[] = {"libc++_shared.so"};
char ROOT_KEY[256] = {0};
int PORT = 0;
std::atomic<bool> g_heartbeat{true};

class InjectSuInfo {
public:
    std::atomic<bool> working{false};
    std::atomic<bool> success{false};
    void set_app_name(const std::string & app_name) {
        std::lock_guard<std::mutex> guard(m_msgLock);
        m_app_name = app_name;
    }
    std::string get_app_name() {
        std::lock_guard<std::mutex> guard(m_msgLock);
        return m_app_name;
    }
    
    void append_console_msg(const std::string & console) {
        std::lock_guard<std::mutex> guard(m_msgLock);
        m_consoleMsg = console + "\n";
    }
    void clear_console_msg() {
        std::lock_guard<std::mutex> guard(m_msgLock);
        m_consoleMsg = "";
    }
    std::string get_console_msg() {
        std::lock_guard<std::mutex> guard(m_msgLock);
        return m_consoleMsg;
    }

private:
    std::string m_app_name;
    std::string m_consoleMsg;
    std::mutex m_msgLock;
} g_inject_su_info;

std::tuple<std::string, bool> handle_index() {
	std::string gzip_html;
	gzip_html.assign(reinterpret_cast<const char*>(web_server::index_html_gz_data), web_server::index_html_gz_size);
	return { gzip_html, true };
}

std::string handle_heartbeat(const std::string & json) {
    g_heartbeat = true;
    std::string userName = get_json_str(json, "userName");
    return convert_2_json(userName);
}

std::string handle_test_root() {
    std::string test_report = kernel_root::get_root_test_report(ROOT_KEY);
    return convert_2_json(test_report);
}

std::string handle_run_root_cmd(const std::string & json) {
    std::string cmd = get_json_str(json, "cmd");
    std::string result;
    KRootErr err = kernel_root::run_root_cmd(ROOT_KEY, cmd.c_str(), result);

    std::stringstream sstr;
    sstr << "run_root_cmd " << to_string(err).c_str() << ", result: " << result;
    return convert_2_json(sstr.str());
}

std::string handle_run_exec_process(const std::string & json) {
    std::string path = get_json_str(json, "path");
    KRootErr err = kernel_root::root_exec_process(ROOT_KEY, path.c_str());

    std::stringstream sstr;
    sstr << "root_exec_processs " << to_string(err).c_str();
    return convert_2_json(sstr.str());
}

std::string handle_install_su() {
    KRootErr err = KRootErr::OK;
    std::string su_hide_full_path;
    err = kernel_root::install_su(ROOT_KEY, su_hide_full_path);
    
    std::stringstream sstr;
    sstr << "install su " << to_string(err).c_str() << ", su_hide_full_path:" << su_hide_full_path << std::endl;
    
    if (is_ok(err)) {
        sstr << "install su done."<< std::endl;
    }
    std::map<std::string, std::string> param;
    param["su_hide_full_path"] = su_hide_full_path;
    param["err"] = to_string(err);
    param["ok"] = is_ok(err) ? "1" : "0";
    return convert_2_json(sstr.str(), param);
}

std::string handle_uninstall_su() {
    KRootErr err = kernel_root::uninstall_su(ROOT_KEY);
    std::stringstream sstr;
    sstr << "uninstall su " << to_string(err).c_str() << std::endl;
    if (is_failed(err)) {
        return convert_2_json(sstr.str());
    }
    sstr << "uninstall su done.";
    
    std::map<std::string, std::string> param;
    param["err"] = to_string(err);
    param["ok"] = is_ok(err) ? "1" : "0";
    return convert_2_json(sstr.str(), param);
}

std::string handle_get_app_list(const std::string & json) {
    bool isShowSystemApp = !!get_json_int(json, "showSystemApp");
    bool isShowThirtyApp = !!get_json_int(json, "showThirdApp");
    bool isShowRunningAPP = !!get_json_int(json, "showRunningApp");

    std::vector<std::string> packageNames;
    std::string cmd;
    if(isShowSystemApp && isShowThirtyApp) cmd = "pm list packages";
    else if(isShowSystemApp) cmd = "pm list packages -s";
    else if(isShowThirtyApp) cmd = "pm list packages -3";

    std::string packages;
    KRootErr err = kernel_root::run_root_cmd(ROOT_KEY, cmd.c_str(), packages);
    if (is_failed(err)) return convert_2_json_v(packageNames);

    std::map<pid_t, std::string> pid_map;
    if(isShowRunningAPP) {
        err = kernel_root::get_all_cmdline_process(ROOT_KEY, pid_map);
        if (is_failed(err)) return convert_2_json_v(packageNames);        
    }    
    // remove "package:" flag
    std::istringstream iss(packages);
    std::string line;
    while (getline(iss, line)) {
        size_t pos = line.find("package:");
        if (pos != std::string::npos) {
            line.erase(pos, std::string("package:").length());
        }
        if(isShowRunningAPP) {
            bool isFound = false;
            for(auto & item : pid_map) {
                if(item.second.find(line) == std::string::npos) continue;
                isFound = true;
                break;
            }
            if(!isFound) continue;
        }
        packageNames.push_back(line);
    }
    return convert_2_json_v(packageNames);
}

void inject_su_thread() {
    writeToLog("inject_su_thread enter");

	std::string su_file_path;
    KRootErr err = kernel_root::install_su(ROOT_KEY, su_file_path);
    std::string su_dir_path = std::filesystem::path(su_file_path).parent_path().string() + "/";

    g_inject_su_info.append_console_msg("su_dir_path ret val: " + su_dir_path);

    // 1.杀光所有历史进程
    std::set<pid_t> out;
    err = kernel_root::find_all_cmdline_process(ROOT_KEY, g_inject_su_info.get_app_name().c_str(), out);
    g_inject_su_info.append_console_msg("find_all_cmdline_process " + to_string(err) + ", cnt:" + std::to_string(out.size()));
    if (is_failed(err)) {
        g_inject_su_info.working = false;
        return;
    }

    for (pid_t pid : out) { kernel_root::kill_process(ROOT_KEY, pid); }

	// 2.注入su环境变量到指定进程
	g_inject_su_info.append_console_msg("waiting for process creation:" + g_inject_su_info.get_app_name());

    pid_t pid;
	err = kernel_root::wait_and_find_cmdline_process(
		ROOT_KEY, g_inject_su_info.get_app_name().c_str(), 60 * 1000, pid);
    g_inject_su_info.append_console_msg("waiting for process creation " + to_string(err));
    if (is_failed(err)) {
        g_inject_su_info.working = false;
        return;
    }
	err = kernel_root::inject_process_env64_PATH_wrapper(ROOT_KEY, pid, su_dir_path.c_str(), kernel_root::ApiOffsetReadMode::OnlyReadFile);
    g_inject_su_info.append_console_msg("inject su " + to_string(err) + ", errmsg: " + strerror(errno));
    g_inject_su_info.success = true;
    g_inject_su_info.working = false;
}

std::string handle_inject_su_in_temp_app(const std::string & json) {
    std::string app_name = get_json_str(json, "appName");
    std::map<std::string, std::string> param;
    param["errcode"] = "0";
    if(g_inject_su_info.working) {
        param["errcode"] = "-1";
        return convert_2_json("inject su thread already running.", param);
    }
    
    if(app_name.empty()) {
        param["errcode"] = "-2";
        return convert_2_json("app name is empty.", param);
    }
    g_inject_su_info.set_app_name(app_name);
    writeToLog("start inject su thread, app name: " + app_name);
    g_inject_su_info.working = true;
    g_inject_su_info.success = false;
    std::thread td(inject_su_thread);
    td.detach();
    return convert_2_json("ok", param);
}

std::string handle_get_inject_su_in_temp_app_result() {
    //writeToLog("handle_get_inject_su_result enter");
    std::map<std::string, std::string> param;
    param["working"] = g_inject_su_info.working ? "1" : "0";
    param["success"] = g_inject_su_info.success ? "1" : "0";

    std::string console = g_inject_su_info.get_console_msg();
    g_inject_su_info.clear_console_msg();

    return convert_2_json(console, param);
}

std::string handle_get_precheck_app_file_list(const std::string & json) {
    std::string app_name = get_json_str(json, "appName");
    std::stringstream errmsg;
    std::map<std::string, std::string> output_file_path;
    std::set<pid_t> pid_arr;
	KRootErr err = kernel_root::find_all_cmdline_process(ROOT_KEY, app_name.c_str(), pid_arr);
	if (is_failed(err)) {
        errmsg << "find_all_cmdline_process " << to_string(err).c_str() << std::endl;
		return convert_2_json_m(errmsg.str());
	}
	if (pid_arr.size() == 0) {
        errmsg << "请先运行目标APP: " << app_name.c_str() << std::endl;
		return convert_2_json_m(errmsg.str());
	}

    std::map<std::string, kernel_root::AppDynlibStatus> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, app_name.c_str(), so_path_list);
    if (is_failed(err)) {
        errmsg << "parasite_precheck_app error:" << to_string(err).c_str() << std::endl;
		if(err == KRootErr::ERR_EXIST_32BIT) {
            errmsg << "此目标APP为32位应用，无法寄生" << to_string(err).c_str() << std::endl;
		}
        return convert_2_json_m(errmsg.str());
	}
	if (!so_path_list.size()) {
        errmsg << "无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！" << to_string(err).c_str() << std::endl;
		return convert_2_json_m(errmsg.str());
	}
	
	std::vector<std::tuple<std::string, kernel_root::AppDynlibStatus>> sort_printf;
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::Running) continue;
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::NotRunning) continue;
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : sort_printf) {
		auto file_path = std::get<0>(item);
		auto appDynlibStatus = std::get<1>(item);
		std::filesystem::path filePath(file_path);
		std::string status = appDynlibStatus == kernel_root::AppDynlibStatus::Running ? " (正在运行)" : " (未运行)";
		if(appDynlibStatus == kernel_root::AppDynlibStatus::Running) {
            std::string file_name = filePath.filename().string();
			for(auto x = 0; x < sizeof(recommend_files) / sizeof(recommend_files[0]); x++) {
				if(file_name == recommend_files[x]) {
					status = " (推荐， 正在运行)";
				}
			}
		}
        output_file_path[file_path] = status;
	}
    return convert_2_json_m(errmsg.str(), output_file_path);
}

std::string handle_inject_su_in_forever_app(const std::string & json) {
    std::string app_name = get_json_str(json, "appName");
    std::string filePath = get_json_str(json, "filePath");
    std::stringstream errmsg;
    std::map<std::string, std::string> param;
    param["errcode"] = "0";
    
	std::string su_file_path;
    KRootErr err = kernel_root::install_su(ROOT_KEY, su_file_path);
    std::string su_dir_path = is_ok(err) ? (std::filesystem::path(su_file_path).parent_path().string() + "/") : "";
	if (su_dir_path.empty()) {
        param["errcode"] = "-1";
        return convert_2_json_m("su_dir_path is empty");
    }

    std::set<pid_t> pid_arr;
	err = kernel_root::find_all_cmdline_process(ROOT_KEY, app_name.c_str(), pid_arr);
	if (is_failed(err)) {
        param["errcode"] = "-2";
        errmsg << "find_all_cmdline_process " << to_string(err).c_str() << std::endl;
		return convert_2_json(errmsg.str());
	}
	if (pid_arr.size() == 0) {
        param["errcode"] = "-3";
        errmsg << "请先运行目标APP: " << app_name.c_str() << std::endl;
		return convert_2_json(errmsg.str());
	}

	err = kernel_root::parasite_implant_su_env(ROOT_KEY, app_name.c_str(), filePath.c_str(), su_dir_path.c_str());
	printf("parasite_implant_su_env err:%zd\n", err);
	if (is_failed(err)) {
        param["errcode"] = "-4";
        std::string msg = "parasite_implant_su_env " + to_string(err);
        return convert_2_json(msg);
    }
	for (pid_t pid : pid_arr) { kernel_root::kill_process(ROOT_KEY, pid); }
    return convert_2_json("ok", param);
}

std::string handle_unknow_type() {
    return convert_2_json("unknow command type.");
}

class MyHttpHandler : public CivetHandler {
public:
    bool handleGet(CivetServer* server, struct mg_connection* conn) override {
        const struct mg_request_info* req_info = mg_get_request_info(conn);
        std::string path = req_info->local_uri ? req_info->local_uri : "/";

        writeToLog("Get request:" + path);
        std::string body;
        bool use_gzip = false;
        if(path == "/") {
            // home page
            std::tie(body, use_gzip) = handle_index();
        }
        mg_printf(conn,
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "%s"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n",
            use_gzip ? "Content-Encoding: gzip\r\n" : "", body.size());
        mg_write(conn, body.data(), body.size());
        return true;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn) override {
        char buf[1024];
        int len = mg_read(conn, buf, sizeof(buf) - 1);
        buf[len > 0 ? len : 0] = '\0';

        const struct mg_request_info* req_info = mg_get_request_info(conn);
        std::string path = req_info->local_uri ? req_info->local_uri : "/";
        std::string body(buf);

        writeToLog("POST request:" + path);
        writeToLog("POST body:" + body);

        std::string resp;
        if(path == "/heartbeat") resp = handle_heartbeat(body);
        else if(path == "/testRoot") resp = handle_test_root();
        else if(path == "/runRootCmd") resp = handle_run_root_cmd(body);
        else if(path == "/runExecProc") resp = handle_run_exec_process(body);
        else if(path == "/installSu") resp = handle_install_su();
        else if(path == "/uninstallSu") resp = handle_uninstall_su();
        else if(path == "/getAppList") resp = handle_get_app_list(body);
        else if(path == "/injectSuInTempApp") resp = handle_inject_su_in_temp_app(body);
        else if(path == "/getInjectSuInTempAppResult") resp = handle_get_inject_su_in_temp_app_result();
        else if(path == "/getPrecheckAppFileList") resp = handle_get_precheck_app_file_list(body);
        else if(path == "/injectSuInForeverApp") resp = handle_inject_su_in_forever_app(body);
        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: application/json\r\n"
                  "Connection: close\r\n\r\n%s",
                  resp.c_str());
        return true;
    }
private:
    std::string m_root_key;
    std::string m_config_file_path;
};


int main(int argc, char* argv[]) {
    srand(time(NULL));
    PORT = rand() % 40001 + 20000;
    strncpy(ROOT_KEY, const_cast<char*>(static_inline_web_server_root_key), sizeof(ROOT_KEY) - 1);

    writeToLog("web_server enter");
    if (is_failed(kernel_root::get_root(ROOT_KEY))) {
        writeToLog("web_server root error");
		return 0;
	}

    std::string str_port = std::to_string(PORT);
    const char* options[] = {
        "listening_ports", str_port.c_str(),
        "num_threads", "1",
        NULL
    };

    CivetServer server(options);

    MyHttpHandler handler;
    server.addHandler("/", handler); // /代表所有路径
    
    sleep(1);
    std::string url = "http://127.0.0.1:" + std::to_string(PORT);
    android_open_url(url);

    while (g_heartbeat) {
        g_heartbeat = false;
        usleep(1000 * 1000 * (MAX_HEARTBEAT_TIME_SEC / 2));
    }
    server.close();
	_exit(0);
    return 0;
}