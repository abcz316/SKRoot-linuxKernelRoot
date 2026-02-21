#include "kernel_module_kit_umbrella.h"

#include "su_interactive.h"
#include "idle_killer.h"

int skroot_module_main(const char* root_key, const char* module_private_dir) { return 0; }

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
        m_su_interactive.start();
        fork_sh_process_daemon();

        m_idle_killer.start(std::chrono::seconds(30), [this] {
            _exit(0);
        });

    }

    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        //printf("[module_hide_data_dir] POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());
        std::string resp;
        if(path == "/sendCommand") {
            m_idle_killer.touch();
            m_su_interactive.sendLine(body);
            resp = "OK";
        } else if(path == "/getNewOutput") {
            m_idle_killer.touch();
            resp = m_su_interactive.takeOutput();
        }
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
private:
    void fork_sh_process_daemon() {
        pid_t shell_pid = m_su_interactive.get_shell_pid();
        pid_t ppid = getpid();
        pid_t child = fork();
        if(child == 0) {
            if (setsid() < 0) {
                setpgid(0, 0); 
            }
            signal(SIGPIPE, SIG_IGN);
            wait_parent_exit(m_root_key, ppid);
            printf("[module_hide_sh_exec] kill sh!\n");
            kill(shell_pid, SIGKILL);
            _exit(0);
        }
    }
private:
    std::string m_root_key;
    SuInteractive m_su_interactive;
    IdleKiller m_idle_killer;
};

// SKRoot 模块名片
SKROOT_MODULE_NAME("隐蔽的系统终端")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("提供隐蔽的 sh 执行通道，彻底替代终端类 App，避免终端类 App 带来的特征暴露。")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_UUID32("zse9vkTjLjWXbafvx8Mlh1MTf8SMTUEL")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_hide_sh_exec/update.json")