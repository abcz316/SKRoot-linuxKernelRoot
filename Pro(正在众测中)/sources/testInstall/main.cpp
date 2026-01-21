#include <string.h>
#include <thread>
#include <vector>
#include <map>
#include <sstream>
#include <filesystem>

#include "kernel_module_kit_umbrella.h"
#include "command.h"
#include "exec_process.h"
#include "test.h"

char ROOT_KEY[256] = {0};

void test_install_skroot() {
	KModErr err = skroot_env::install_skroot_environment(ROOT_KEY);
    printf("install_skroot_environment: %s\n", to_string(err).c_str());
	if(is_ok(err)) printf("将在重启后生效\n");
}

void test_uninstall_skroot() {
	KModErr err = skroot_env::uninstall_skroot_environment(ROOT_KEY);
    printf("uninstall_skroot_environment: %s\n", to_string(err).c_str());
	if(is_ok(err)) printf("将在重启后生效\n");
}

void test_show_skroot_state() {
	using SkrootEnvState = skroot_env::SkrootEnvState;
	static std::map<SkrootEnvState, const char*> m = {
        {SkrootEnvState::NotInstalled, "NotInstalled"},
        {SkrootEnvState::Running,      "Running"},
        {SkrootEnvState::Fault,        "Fault"},
    };
	SkrootEnvState state = skroot_env::get_skroot_environment_state(ROOT_KEY);
    printf("get_skroot_environment_state: %s\n", m[state]);
}

void test_show_skroot_ver() {
	skroot_env::SkrootSdkVersion ver;
	KModErr err = skroot_env::get_installed_skroot_environment_version(ROOT_KEY, ver);
	if(is_failed(err)) {
		printf("get_installed_skroot_environment_version err: %s\n", to_string(err).c_str());
		return;
	}
    printf("get_installed_skroot_environment_version: %s, %d.%d.%d\n", to_string(err).c_str(), ver.major, ver.minor, ver.patch);
}

void test_show_skroot_log() {
	std::string log;
	KModErr err = skroot_env::read_skroot_log(ROOT_KEY, log);
    printf("%s\n", log.c_str());
    printf("read_skroot_log: %s\n", to_string(err).c_str());
}

void test_root() {
	printf("%s\n", get_root_test_report(ROOT_KEY));
}

void test_run_root_cmd(int argc, char* argv[]) {
	std::stringstream sstrCmd;
	for (int i = 0; i < argc; i++) {
		sstrCmd << argv[i];
		if (i != (argc - 1)) {
			sstrCmd << " ";
		}
	}
	printf("test_run_root_cmd(%s)\n", sstrCmd.str().c_str());

	std::string result;
	bool ret = run_root_cmd(ROOT_KEY, sstrCmd.str().c_str(), result);
	printf("test_run_root_cmd ret:%s\n", ret ? "OK" : "FAILED");
	printf("test_run_root_cmd result:%s\n", result.c_str());
}

void test_root_exec_process(int argc, char* argv[]) {
	std::stringstream ss;
	for (int i = 0; i < argc; i++) {
		ss << argv[i];
		if (i != (argc - 1)) {
			ss << " ";
		}
	}
	printf("test_root_exec_process(%s)\n", ss.str().c_str());

	bool ret = root_exec_process(ROOT_KEY, ss.str().c_str());
	printf("root_exec_process ret:%s\n", ret ? "OK" : "FAILED");
}

void test_add_su_list(const char* app_package_name) {
	KModErr err = skroot_env::add_su_auth_list(ROOT_KEY, app_package_name);
	printf("add_su_auth_list err: %s\n", to_string(err).c_str());
}

void test_remove_su_list(const char* app_package_name) {
	KModErr err = skroot_env::remove_su_auth_list(ROOT_KEY, app_package_name);
	printf("remove_su_auth_list err: %s\n", to_string(err).c_str());
}

void test_show_su_list() {
	std::vector<skroot_env::su_auth_item> pkgs;
    KModErr err = skroot_env::get_su_auth_list(ROOT_KEY, pkgs);
    printf("get_su_auth_list err: %s, cnt:%zd\n", to_string(err).c_str(), pkgs.size());
    for(auto & item : pkgs) {
    	printf("su app: %s\n", item.app_package_name);
    }
}

void test_clear_su_list() {
	KModErr err = skroot_env::clear_su_auth_list(ROOT_KEY);
	printf("clear_su_auth_list err: %s\n", to_string(err).c_str());
}

void test_add_module(const char* zip_file_path) {
	std::string reason;
	KModErr err = skroot_env::install_module(ROOT_KEY, zip_file_path, reason);
	if(is_ok(err)) {
		printf("install_module: %s\n", to_string(err).c_str());
		printf("将在重启后生效\n");
	} else {
		printf("install_module err: %s, reason: %s\n", to_string(err).c_str(), reason.c_str());
	}
}

void test_remove_module(const char* mod_uuid) {
	KModErr err = skroot_env::uninstall_module(ROOT_KEY, mod_uuid);
	printf("uninstall_module err: %s\n", to_string(err).c_str());
	if(is_ok(err)) printf("将在重启后生效\n");
}

static void print_sep(char c) {
    for (int i = 0; i < 32; ++i) std::putchar(c);
    std::putchar('\n');
}
static void print_desc_info(const skroot_env::module_desc& desc) {
    printf("----- SKRoot Module Meta -----\n");
    printf("Name    : %s\n", desc.name);
    printf("Version : %s\n", desc.version);
    printf("Desc    : %s\n", desc.desc);
    printf("Author  : %s\n", desc.author);
    printf("UUID    : %s\n", desc.uuid);
    auto & sdk = desc.min_sdk_ver;
    printf("MinSDK  : %u.%u.%u\n", sdk.major, sdk.minor, sdk.patch);
	
	bool online_update = !!strlen(desc.update_json);
    bool any_feature = desc.web_ui || online_update;
    if (any_feature) {
        std::puts("Features:");
		if(desc.web_ui) std::printf("  [+] Web UI\n");
		if(online_update) std::printf("  [+] Online Update\n");
    }
    printf("------------------------------\n");
}
void test_show_module_list() {
	std::vector<skroot_env::module_desc> list1;
	std::vector<skroot_env::module_desc> list2;
	KModErr err1 = skroot_env::get_all_modules_list(ROOT_KEY, list1, skroot_env::ModuleListMode::All);
	KModErr err2 = skroot_env::get_all_modules_list(ROOT_KEY, list2, skroot_env::ModuleListMode::RunningOnly);
    printf("get_all_modules_list(All) err: %s, cnt:%zd\n", to_string(err1).c_str(), list1.size());
    printf("get_all_modules_list(RunningOnly) err: %s, cnt:%zd\n", to_string(err2).c_str(), list2.size());
	if(is_ok(err1)) {
		printf("All modules list:\n");
		for(auto & m : list1) print_desc_info(m);
	}
	if(is_ok(err2)) {
		printf("Running modules list:\n");
		for(auto & m : list2) printf("name:%s, uuid:%s\n", m.name, m.uuid);
	}
}

void test_parse_module(const char* zip_file_path) {
	skroot_env::module_desc desc;
	KModErr err = skroot_env::parse_module_desc_from_zip_file(ROOT_KEY, zip_file_path, desc);
	printf("parse_module_desc_from_zip_file err: %s\n", to_string(err).c_str());
	if(is_ok(err)) print_desc_info(desc);
}

void test_open_module_web_ui(const char* mod_uuid) {
	int port = 0;
    KModErr err = skroot_env::features::web_ui::start_module_web_ui_server_async(ROOT_KEY, mod_uuid, port);
    printf("start_module_web_ui_server_async err: %s, port:%d\n", to_string(err).c_str(), port);
    while(1) {
        sleep(1);
    }
}

int main(int argc, char* argv[]) {
	printf(
		"=======================================================\n"
		"本工具名称: SKRoot(Pro) - Linux内核级完美隐藏ROOT演示\n"
		"用法总览:\n"
		"testInstall <command> [args...]\n"
		"---------------------- 基础环境 ----------------------\n");

	printf("%-29s %s\n", "install", "安装 SKRoot 环境");
	printf("%-29s %s\n", "uninstall", "卸载 SKRoot 环境");
	printf("%-29s %s\n", "show-state", "获取当前 SKRoot 环境状态");
	printf("%-29s %s\n", "show-ver", "查看已安装 SKRoot 版本");
	printf("%-29s %s\n\n", "show-log", "查看 SKRoot 开机日志");

	printf("------------------ 权限测试与执行 ------------------\n");
	printf("%-29s %s\n", "test", "测试 ROOT 权限");
	printf("%-29s %s\n", "cmd <command>", "执行 ROOT 命令");
	printf("%-29s %s\n\n","exec <file-path>", "以 ROOT 身份直接执行程序");

	printf("------------------ SU 授权列表管理 ------------------\n");
	printf("%-29s %s\n", "su-list add <package>", "将 APP 加入 SU 授权列表");
	printf("%-29s %s\n", "su-list remove <package>", "将 APP 移出 SU 授权列表");
	printf("%-29s %s\n", "su-list show", "显示 SU 授权列表");
	printf("%-29s %s\n\n", "su-list clear", "清空 SU 授权列表");

	printf("---------------------- 模块管理 ----------------------\n");
	printf("%-29s %s\n", "module add <zip_file_path>", "添加 SKRoot 模块");
	printf("%-29s %s\n", "module remove <mod_uuid>", "移除 SKRoot 模块");
	printf("%-29s %s\n", "module list", "显示 SKRoot 模块列表");
	printf("%-29s %s\n\n", "module desc <zip_file_path>", "解析 SKRoot 模块的描述信息");
	printf("%-29s %s\n\n", "module webui <mod_uuid>", "打开 SKRoot 模块 WebUI 页面");

	printf("-------------------------------------------------------\n"
		"本工具特点：\n"
		"新一代SKRoot，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，兼容安卓APP直接JNI稳定调用。\n"
		"如需帮助，请使用对应的命令，或者查看上面的菜单。\n\n");
	++argv;
	--argc;
	if (argc < 1) {
		std::cout << "error param." << std::endl;
		return 0;
	}

	//TODO: 在此修改你的Root key值。
	strncpy(ROOT_KEY, "vzXtDKDAltAGxHtMGRZZfVouy90dgNqFsLM6UGeqb6OgH0VX", sizeof(ROOT_KEY) - 1);

	std::map<std::string, std::function<void()>> command_map = {
		{"install", []() { test_install_skroot(); }},
		{"uninstall", []() { test_uninstall_skroot(); }},
		{"show-state", []() { test_show_skroot_state(); }},
		{"show-ver", []() { test_show_skroot_ver(); }},
		{"show-log", []() { test_show_skroot_log(); }},
		{"test", []() { test_root(); }},
		{"cmd", [argc, argv]() { test_run_root_cmd(argc - 1, argv + 1); }},
		{"exec", [argc, argv]() { test_root_exec_process(argc - 1, argv + 1); }},
		{"su-list", [argv]() {
			const std::string sub = argv[1];
			if(sub == "add") test_add_su_list(argv[2]);
			else if(sub == "remove") test_remove_su_list(argv[2]);
			else if(sub == "show") test_show_su_list();
			else if(sub == "clear") test_clear_su_list();
		}},
		{"module", [argv]() {
			const std::string sub = argv[1];
			if(sub == "add") test_add_module(argv[2]);
			else if(sub == "remove") test_remove_module(argv[2]);
			else if(sub == "list") test_show_module_list();
			else if(sub == "desc") test_parse_module(argv[2]);
			else if(sub == "webui") test_open_module_web_ui(argv[2]);
		}}
	};

	std::string cmd = argv[0];
	if (command_map.find(cmd) != command_map.end()) {
		command_map[cmd]();
	} else {
		std::cout << "unknown command." << std::endl;
		return 1;
	}
	return 0;
}