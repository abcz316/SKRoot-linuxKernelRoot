#include "testRoot.h"

// TODO：请将此处的KEY替换为你的内核ROOT KEY
#define ROOT_KEY "bz4kKoPVSAG1tnwlcs1PJ1qp6HtVymj60CoTgsjmMd1UALve"

namespace {
constexpr const char* k_su_base_path = "/data/local/tmp";
constexpr const char* recommend_files[] = {"libc++_shared.so"};

}

void show_id() {
	printf("%s\n", get_capability_info().c_str());
}

void test_root() {
	// 获取ROOT权限
	printf("%s\n", get_capability_info().c_str());

	printf("get_root ret:%zd\n", kernel_root::get_root(ROOT_KEY));

	printf("%s\n", get_capability_info().c_str());
}

void test_run_root_cmd(int argc, char* argv[]) {
	// 执行ROOT命令
	std::stringstream sstrCmd;
	for (int i = 0; i < argc; i++) {
		sstrCmd << argv[i];
		if (i != (argc - 1)) {
			sstrCmd << " ";
		}
	}
	printf("test_run_root_cmd(%s)\n", sstrCmd.str().c_str());

	ssize_t err;
	std::string result = kernel_root::run_root_cmd(ROOT_KEY, sstrCmd.str().c_str(), err);
	printf("test_run_root_cmd err:%zd\n", err);
	printf("test_run_root_cmd result:%s\n", result.c_str());
}

void test_run_init64_cmd(int argc, char* argv[]) {
	// 执行原生内核命令
	std::stringstream sstrCmd;
	for (int i = 0; i < argc; i++) {
		sstrCmd << argv[i];
		if (i != (argc - 1)) {
			sstrCmd << " ";
		}
	}
	printf("test_run_init64_cmd(%s)\n", sstrCmd.str().c_str());

	ssize_t err;
	std::string result = kernel_root::run_init64_cmd_wrapper(ROOT_KEY, sstrCmd.str().c_str(), err);
	printf("run_init64_cmd_wrapper err:%zd\n", err);
	printf("run_init64_cmd_wrapper result:%s\n", result.c_str());
}

void test_install_su_env() {
	// 安装部署su
	ssize_t err;
	std::string su_hide_name = kernel_root::install_su(ROOT_KEY, k_su_base_path, err);
	printf("install su hide full path:%s, err:%zd\n", su_hide_name.c_str(),
		   err);
}

void test_su_env_temp_inject(const char* target_pid_cmdline) {
	if (kernel_root::get_root(ROOT_KEY) != 0) {
		return;
	}

	// 1.获取su_xxx隐藏目录
	std::string su_hide_path = kernel_root::su::find_su_hide_folder_path(k_su_base_path, "su");
	printf("su_hide_path ret val:%s\n", su_hide_path.c_str());
	if (su_hide_path.empty()) { return; }

	// 2.杀光所有历史进程
	std::set<pid_t> out;
	ssize_t err = kernel_root::find_all_cmdline_process(
		ROOT_KEY, target_pid_cmdline, out);
	printf("find_all_cmdline_process err:%zd, cnt:%zu\n", err, out.size());
	if (err) { return; }
	for (pid_t pid : out) { kernel_root::kill_process(ROOT_KEY, pid); }

	// 3.注入su环境变量到指定进程
	printf("test_auto_su_env_inject Waiting for process creation(%s)\n", target_pid_cmdline);
	pid_t pid;
	err = kernel_root::wait_and_find_cmdline_process(
		ROOT_KEY, target_pid_cmdline, 60 * 1000, pid);
	printf("wait_and_find_cmdline_process(%zd)\n", err);

	err = kernel_root::inject_process_env64_PATH_wrapper(ROOT_KEY, pid,
														 su_hide_path.c_str());
	printf("inject_process_env64_PATH_wrapper ret val:%zd, error:%s\n", err,
		   strerror(errno));
}

void test_su_env_forever_inject(const char* target_pid_cmdline) {
	if (kernel_root::get_root(ROOT_KEY) != 0) {
		return;
	}
	// 1.获取su_xxx隐藏目录
	std::string su_hide_path = kernel_root::su::find_su_hide_folder_path(k_su_base_path, "su");
	printf("su_hide_path ret val:%s\n", su_hide_path.c_str());
	if (su_hide_path.empty()) { return; }

	// 2.寄生预检目标APP
	std::set<pid_t> pid_arr;
	ssize_t err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, pid_arr);
	if (err) {
		printf("find_all_cmdline_process err:%zd\n", err);
		return;
	}
	if (pid_arr.size() == 0) {
		printf("请先运行目标APP: %s\n", target_pid_cmdline);
		return;
	}
	std::map<std::string, kernel_root::app_so_status> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, target_pid_cmdline, so_path_list);
	if (err) {
		printf("parasite_precheck_app error:%zd\n", err);
		if(err == -9904) {
			printf("此目标APP为32位应用，无法寄生\n");
		}
		return;
	}
	if (!so_path_list.size()) {
		printf("无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！\n");
		return;
	}
	printf("请在以下的目标APP文件列表中选择一个即将要被寄生的文件:\n");

	std::vector<std::tuple<std::string, kernel_root::app_so_status>> sort_printf;
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::app_so_status::running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::app_so_status::not_running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : sort_printf) {
		auto file_path = std::get<0>(item);
		auto app_so_status = std::get<1>(item);
		std::filesystem::path filePath(file_path);
		std::string file_name = filePath.filename().string();
		std::string status = app_so_status == kernel_root::app_so_status::running ? "(正在运行)" : "(未运行)";
		if(app_so_status == kernel_root::app_so_status::running) {
			for(auto x = 0; x < sizeof(recommend_files) / sizeof(recommend_files[0]); x++) {
				if(file_name == recommend_files[x]) {
					status = "(推荐， 正在运行)";
				}
			}
		}
		printf("\t%s %s\n", file_name.c_str(), status.c_str());
	}
	printf("\n");
	printf("请输入将要被寄生的文件名称: ");
	std::string user_input_so_name;
	std::getline(std::cin, user_input_so_name);
	printf("\n");
	auto it = std::find_if(so_path_list.begin(), so_path_list.end(), 
        [&](const auto& s) { return s.first.find(user_input_so_name) != std::string::npos; });
    if (it == so_path_list.end()) {
		printf("Not found: %s\n", user_input_so_name.c_str());
		return;
    }
	
	// 3.寄生植入目标APP
	err = kernel_root::parasite_implant_su_env(ROOT_KEY, target_pid_cmdline, it->first.c_str(), su_hide_path);
	printf("parasite_implant_su_env err:%zd\n", err);
	if(err) { return; }

	// 4.杀光所有历史进程
	for (pid_t pid : pid_arr) { kernel_root::kill_process(ROOT_KEY, pid); }
}

void test_clean_su_env() {
	// 完全卸载清理su
	ssize_t err = kernel_root::uninstall_su(ROOT_KEY, k_su_base_path, "su");
	printf("uninstall_su err:%zd\n", err);
}

void test_implant_app(const char* target_pid_cmdline) {
	// 1.寄生预检目标APP
	std::set<pid_t> pid_arr;
	ssize_t err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, pid_arr);
	if (err) {
		printf("find_all_cmdline_process err:%zd\n", err);
		return;
	}
	if (pid_arr.size() == 0) {
		printf("请先运行目标APP: %s\n", target_pid_cmdline);
		return;
	}
	std::map<std::string, kernel_root::app_so_status> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, target_pid_cmdline, so_path_list);
	if (err) {
		printf("parasite_precheck_app error:%zd\n", err);
		if(err == -9904) {
			printf("此目标APP为32位应用，无法寄生\n");
		}
		return;
	}
	if (!so_path_list.size()) {
		printf("无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！\n");
		return;
	}
	printf("请在以下的目标APP文件列表中选择一个即将要被寄生的文件:\n");

	std::vector<std::tuple<std::string, kernel_root::app_so_status>> sort_printf;
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::app_so_status::running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::app_so_status::not_running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
		for (const auto& item : sort_printf) {
		auto file_path = std::get<0>(item);
		auto app_so_status = std::get<1>(item);
		std::filesystem::path filePath(file_path);
		std::string file_name = filePath.filename().string();
		std::string status = app_so_status == kernel_root::app_so_status::running ? "(正在运行)" : "(未运行)";
		if(app_so_status == kernel_root::app_so_status::running) {
			for(auto x = 0; x < sizeof(recommend_files) / sizeof(recommend_files[0]); x++) {
				if(file_name == recommend_files[x]) {
					status = "(推荐， 正在运行)";
				}
			}
		}
		printf("\t%s %s\n", file_name.c_str(), status.c_str());
	}
	printf("\n");
	printf("请输入将要被寄生的文件名称: ");
	std::string user_input_so_name;
	std::getline(std::cin, user_input_so_name);
	printf("\n");
	auto it = std::find_if(so_path_list.begin(), so_path_list.end(), 
        [&](const auto& s) { return s.first.find(user_input_so_name) != std::string::npos; });
    if (it == so_path_list.end()) {
		printf("Not found: %s\n", user_input_so_name.c_str());
		return;
    }
	
	// 2.寄生植入目标APP
	err = kernel_root::parasite_implant_app(ROOT_KEY, target_pid_cmdline, it->first.c_str());
	printf("parasite_implant_app err:%zd\n", err);
	if(err) { return; }

	// 3.杀光所有历史进程
	for (pid_t pid : pid_arr) { kernel_root::kill_process(ROOT_KEY, pid); }
}

int main(int argc, char* argv[]) {
	printf(
		"======================================================\n"
		"本工具名称: Linux ARM64 完美隐藏ROOT演示\n\n"
		"本工具功能列表：\n"

		"1. 显示自身权限信息\n"
		"\tUsage: testRoot id\n\n"

		"2. 获取ROOT权限\n"
		"\tUsage: testRoot get\n\n"

		"3. 执行ROOT命令\n"
		"\tUsage: testRoot cmd <command>\n\n"

		"4. 执行原生内核命令\n"
		"\tUsage: testRoot init <command>\n\n"

		"5. 安装部署su\n"
		"\tUsage: testRoot su\n\n"

		"6. 临时注入su到指定进程\n"
		"\tUsage: testRoot process <process-name>\n\n"

		"7. 永久注入su到指定进程\n"
		"\tUsage: testRoot implantSu <process-name>\n\n"

		"8. 完全卸载清理su\n"
		"\tUsage: testRoot cleansu\n\n"

		"9. 寄生目标APP\n"
		"\tUsage: testRoot implantApp <process-name> <so-name>\n\n"

		"本工具特点：\n"
		"新一代SKRoot，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，兼容安卓APP直接JNI稳定调用。\n"
		"======================================================\n"
		"为了实现最佳隐蔽性，推荐使用 [寄生目标APP] 功能，寄生到能常驻后台且联网的APP上，如音乐类、播放器类、运动类、广播类、社交聊天类APP\n\n"
		"如需帮助，请使用对应的命令，或者查看上面的菜单。\n\n");
	++argv;
	--argc;
	if (argc == 0) {
		std::cout << "error param." << std::endl;
		return 0;
	}
	std::map<std::string, std::function<void()>> command_map = {
		{"id", []() { show_id(); }},
		{"get", []() { test_root(); }},
		{"cmd", [argc, argv]() { test_run_root_cmd(argc - 1, argv + 1); }},
		{"init", [argc, argv]() { test_run_init64_cmd(argc - 1, argv + 1); }},
		{"su", []() { test_install_su_env(); }},
		{"suTemp", [argv]() { test_su_env_temp_inject(argv[1]); }},
		{"suForever", [argv]() { test_su_env_forever_inject(argv[1]); }},
		{"cleansu", []() { test_clean_su_env(); }},
		{"implantApp", [argv]() { test_implant_app(argv[1]); }}
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