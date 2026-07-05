
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <chrono>
#include <ctime>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <cerrno>
#include <cstring>
#include <vector>

#include "kernel_module_kit_umbrella.h"

#include "su_interactive.h"
#include "idle_killer.h"
#include "json_helper.h"
#include "url_encode_utils.h"
#include "list_dir_helper.h"
#include "simple_hash_util.h"

#define WORK_DIR_NAME "work"
#define MAX_QUICK_ACTIONS 10
#define RECORD_CMD_LEN 100

namespace fs = std::filesystem;

int skroot_module_main(const char* root_key, const char* module_private_dir) { return 0; }

static void append_or_move_to_back(std::vector<std::string>& vec, const std::string& target) {
    auto it = std::find(vec.begin(), vec.end(), target);
    if (it != vec.end()) {
        if (it + 1 != vec.end()) std::rotate(it, it + 1, vec.end());
    } else {
        vec.push_back(target);
    }
}

static void add_quick_actions(const std::vector<std::string>& cmd) {
    if (!cmd.size()) return;
    std::string json;
    kernel_module::read_string_disk_storage("quick_actions", json);
    std::vector<std::string> cmd_arr = parse_json(json);
    for(auto & c : cmd) {
        std::vector<char> encoded_buf(c.size() * 3 + 1, '\0');
        url_encode(c.c_str(), encoded_buf.data());
        std::string encoded_str(encoded_buf.data(), std::strlen(encoded_buf.data()));
        append_or_move_to_back(cmd_arr, encoded_str);
    }
    while (cmd_arr.size() > MAX_QUICK_ACTIONS) {
        cmd_arr.erase(cmd_arr.begin());
    }
    json = json_array_from_set(cmd_arr);
    kernel_module::write_string_disk_storage("quick_actions", json.c_str());
}

static std::string read_quick_actions_json() {
    std::string json;
    kernel_module::read_string_disk_storage("quick_actions", json);
    if(json.empty()) json = "[]";
    return json;
}

static void write_terminal_keep_mode(bool enabled) {
    kernel_module::write_bool_disk_storage("terminal_keep_mode", enabled);
}

static bool read_terminal_keep_mode() {
    bool enabled = false;
    kernel_module::read_bool_disk_storage("terminal_keep_mode", enabled);
    return enabled;
}

static void create_work_dir(const char* module_private_dir, const char* work_dir_name) {
    fs::path work_dir = fs::path(module_private_dir) / work_dir_name;
    std::error_code ec;
    fs::create_directories(work_dir, ec);
    ::chmod(work_dir.c_str(), 0777);
    const char* selinux_flag = "u:object_r:system_file:s0";
    ::setxattr(work_dir.c_str(), XATTR_NAME_SELINUX, selinux_flag, std::strlen(selinux_flag) + 1, 0);
}

std::string module_on_install(const char* root_key, const char* module_private_dir) {
    add_quick_actions({"getenforce", "ls /", "id"});
    create_work_dir(module_private_dir, WORK_DIR_NAME);
    return "";
}

static bool pid_alive(pid_t pid) {
    if (pid <= 1) return false;
    if (::kill(pid, 0) == 0) return true;
    return errno == EPERM;
}

static void wait_parent_exit(const std::string& root_key, pid_t ppid) {
    timespec ts{0, 500 * 1000 * 1000}; // 500ms
    while (getppid() != 1 && pid_alive(ppid)) {
        skroot_env::get_root(root_key.c_str());
        nanosleep(&ts, nullptr);
    }
}


// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        m_root_key = root_key;

        m_hide_dir = (fs::path(module_private_dir) / WORK_DIR_NAME).string();
        m_keep_terminal = read_terminal_keep_mode();
        m_su_interactive.start(module_private_dir);
        if (!m_keep_terminal) {
            fork_sh_process_daemon();
        }
        m_idle_killer.start(std::chrono::seconds(20), [this]() -> bool {
            if (m_keep_terminal) {
                if (!m_su_interactive.isShellForeground()) {
                    // 当前 shell 不在前台，说明可能有用户后台程序在跑。
                    // 这次不杀，IdleKiller 继续监控。
                    return false;
                }
                printf("[module_hide_sh_exec] shell foreground, idle kill!\n");
            } else {
                printf("[module_hide_sh_exec] idle kill!\n");
            }
            if (m_server) m_server->close();
            m_su_interactive.stop(true);
            _exit(0);
            return true;
        });
    }

    void onServerCreated(CivetServer* server) override {
        m_server = server;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        //printf("[module_hide_sh_exec] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());
        std::string resp;
        if(path == "/sendCommand") resp = handle_send_command(body);
        else if(path == "/getNewOutput") resp = handle_get_new_output(body);
        else if(path == "/getQuickActions") resp = handle_get_quick_actions(body);
        else if(path == "/listDir") resp = handle_list_dir(body);
        else if(path == "/getAutoTasks") resp = handle_get_auto_tasks();
        else if(path == "/saveAutoTasks") resp = handle_save_auto_tasks(body);
        else if(path == "/getHideDir") resp = handle_get_hide_dir();
        else if(path == "/checkFileType") resp = handle_check_file_type(body);
        else if(path == "/checkExecMount") resp = handle_check_exec_mount(body);
        else if(path == "/getTerminalKeepMode") resp = handle_get_terminal_keep_mode();
        else if(path == "/saveTerminalKeepMode") resp = handle_save_terminal_keep_mode(body);
        else if(path == "/exitWebui") resp = handle_exit_webui();

        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }

    ServerExitAction onBeforeServerExit() override { return ServerExitAction::KeepRunning; }

private:
    void fork_sh_process_daemon() {
        pid_t shell_pid = m_su_interactive.get_shell_pid();
        if (shell_pid <= 0) return;

        pid_t ppid = getpid();
        pid_t child = fork();
        if(child == 0) {
            wait_parent_exit(m_root_key, ppid);
            printf("[module_hide_sh_exec] kill sh: %d\n", shell_pid);
            kill(shell_pid, SIGKILL);
            _exit(0);
        }
    }

    std::string handle_send_command(const std::string& body) {
        m_idle_killer.touch();
        if(body == "su") return "OK";
        m_su_interactive.sendLine(body);
        if (!body.empty() && body.length() < RECORD_CMD_LEN) {
            add_quick_actions({body});
        }
        return "OK";
    }

    std::string handle_get_new_output(const std::string& body) {
        m_idle_killer.touch();
        return m_su_interactive.takeOutput();
    }

    std::string handle_get_quick_actions(const std::string& body) {
        m_idle_killer.touch();
        return read_quick_actions_json();
    }

    std::string handle_list_dir(const std::string& body) {
        m_idle_killer.touch();
        std::string dir = body.empty() ? "/" : body;
        const std::string special_comm = SimpleHashUtil::to_random_string(m_root_key).data();
        return list_dir_helper::build_list_dir_result_json(dir, special_comm);
    }

    std::string handle_get_auto_tasks() {
        std::string json;
        kernel_module::read_string_disk_storage("auto_tasks", json);
        if(json.empty()) json = "[]";
        return json;
    }

    std::string handle_save_auto_tasks(const std::string& body) {
        kernel_module::write_string_disk_storage("auto_tasks", body.c_str());
        return "OK";
    }
	
    std::string handle_get_hide_dir() { return m_hide_dir; }
	
	std::string handle_check_file_type(const std::string& filepath) {
        m_idle_killer.touch();
        if (filepath.empty()) return "unknown";
        std::error_code ec;
        if (!fs::is_regular_file(filepath, ec)) return "not a file";
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "error reading";
        char buffer[32] = {0};
        file.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = file.gcount();
        if (bytesRead >= 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
            if (bytesRead >= 20) {
                uint16_t machine = *reinterpret_cast<uint16_t*>(&buffer[18]);
                if (machine == 183) return "executable_arm64";
                else if (machine == 40) return "executable_arm32";
                else return "executable_other_elf";
            }
            return "executable_unknown_elf";
        }
        if (bytesRead >= 2 && buffer[0] == '#' && buffer[1] == '!') return "shell_script";
        if (filepath.size() >= 3 && filepath.substr(filepath.size() - 3) == ".sh") return "shell_script";
        return "unknown";
    }
	
	std::string handle_check_exec_mount(const std::string& path) {
        m_idle_killer.touch();
        if (path.empty()) return "Empty path";
        std::error_code ec;
        if (!fs::exists(path, ec)) return "Path does not exist";
        struct statvfs st;
        if (::statvfs(path.c_str(), &st) != 0) return "Failed to get filesystem status";
		bool is_noexec = (st.f_flag & ST_NOEXEC) != 0;
		return is_noexec ? "can not exec" : "can exec";
    }
	
    std::string handle_get_terminal_keep_mode() {
        return read_terminal_keep_mode() ? "1" : "0";
    }

    std::string handle_save_terminal_keep_mode(const std::string& body) {
        write_terminal_keep_mode(body == "1");
        return "OK";
    }

	std::string handle_exit_webui() {
        if(m_server) m_server->close();
        m_su_interactive.stop(true);
        _exit(0);
        return "OK";
    }
private:
    std::string m_root_key;
    CivetServer* m_server = nullptr;
    std::string m_hide_dir;
    bool m_keep_terminal = false;
    SuInteractive m_su_interactive;
    IdleKiller m_idle_killer;
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("隐蔽的系统终端")
SKROOT_MODULE_VERSION("3.1.0")
SKROOT_MODULE_DESC("提供独立隐蔽的 sh 执行通道，彻底替代终端类 App，避免终端类 App 带来的特征暴露。")
SKROOT_MODULE_AUTHOR("SKRoot、斓梦语")
SKROOT_MODULE_ID32("zse9vkTjLjWXbafvx8Mlh1MTf8SMTUEL")
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_sh_exec/update.json")