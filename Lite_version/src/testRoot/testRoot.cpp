#include <string.h>
#include <thread>
#include <vector>
#include <sstream>
#include <filesystem>

#include "rootkit_umbrella.h"

char ROOT_KEY[256] = {0};

namespace {
	constexpr const char* recommend_files[] = {"libc++_shared.so"};
}
void test_root() {
	printf("%s\n", kernel_root::get_root_test_report(ROOT_KEY));
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
	KRootErr err = kernel_root::run_root_cmd(ROOT_KEY, sstrCmd.str().c_str(), result);
	printf("test_run_root_cmd err:%s\n", to_string(err).c_str());
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

	KRootErr err = kernel_root::root_exec_process(ROOT_KEY, ss.str().c_str());
	printf("run_init64_cmd_wrapper err:%s\n", to_string(err).c_str());
}

void test_install_su_env() {
	std::string su_file_path;
    KRootErr err = kernel_root::install_su(ROOT_KEY, su_file_path);
	printf("install su file path:%s, err:%s\n", su_file_path.c_str(), to_string(err).c_str());
}

void test_su_env_temp_inject(const char* target_pid_cmdline) {
	if (is_failed(kernel_root::get_root(ROOT_KEY))) return;

	// 1.获取su_xxx隐藏目录
	std::string su_file_path;
    KRootErr err = kernel_root::install_su(ROOT_KEY, su_file_path);
    std::string su_dir_path = is_ok(err) ? (std::filesystem::path(su_file_path).parent_path().string() + "/") : "";
	if (su_dir_path.empty()) return;

	// 2.杀光所有历史进程
	std::set<pid_t> out;
	err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, out);
	printf("find_all_cmdline_process err:%s, cnt:%zu\n", to_string(err).c_str(), out.size());
	if (is_failed(err)) return;

	for (pid_t pid : out) { kernel_root::kill_process(ROOT_KEY, pid); }

	// 3.注入su环境变量到指定进程
	printf("test_auto_su_env_inject Waiting for process creation(%s)\n", target_pid_cmdline);
	pid_t pid;
	err = kernel_root::wait_and_find_cmdline_process(
		ROOT_KEY, target_pid_cmdline, 60 * 1000, pid);
	printf("wait_and_find_cmdline_process(%s)\n", to_string(err).c_str());

	err = kernel_root::inject_process_env64_PATH_wrapper(ROOT_KEY, pid,
														 su_dir_path.c_str());
	printf("inject_process_env64_PATH_wrapper ret val:%s, error:%s\n", to_string(err).c_str(),
		   strerror(errno));
}

void test_su_env_forever_inject(const char* target_pid_cmdline) {
	if (is_failed(kernel_root::get_root(ROOT_KEY))) return;

	// 1.获取su_xxx隐藏目录
	std::string su_file_path;
    KRootErr err = kernel_root::install_su(ROOT_KEY, su_file_path);
    std::string su_dir_path = is_ok(err) ? (std::filesystem::path(su_file_path).parent_path().string() + "/") : "";
	if (su_dir_path.empty()) return;

	// 2.寄生预检目标APP
	std::set<pid_t> pid_arr;
	err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, pid_arr);
	if (is_failed(err)) {
		printf("find_all_cmdline_process err:%s\n", to_string(err).c_str());
		return;
	}
	if (pid_arr.size() == 0) {
		printf("请先运行目标APP: %s\n", target_pid_cmdline);
		return;
	}
	std::map<std::string, kernel_root::AppDynlibStatus> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, target_pid_cmdline, so_path_list);
	if (is_failed(err)) {
		printf("parasite_precheck_app err:%s\n", to_string(err).c_str());
		if(err == KRootErr::ERR_EXIST_32BIT) {
			printf("此目标APP为32位应用，无法寄生\n");
		}
		return;
	}
	if (!so_path_list.size()) {
		printf("无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！\n");
		return;
	}
	printf("请在以下的目标APP文件列表中选择一个即将要被寄生的文件:\n");

	std::vector<std::tuple<std::string, kernel_root::AppDynlibStatus>> sort_printf;
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::Running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::NotRunning) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : sort_printf) {
		auto file_path = std::get<0>(item);
		auto app_so_status = std::get<1>(item);
		std::filesystem::path filePath(file_path);
		std::string file_name = filePath.filename().string();
		std::string status = app_so_status == kernel_root::AppDynlibStatus::Running ? "(正在运行)" : "(未运行)";
		if(app_so_status == kernel_root::AppDynlibStatus::Running) {
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
	err = kernel_root::parasite_implant_su_env(ROOT_KEY, target_pid_cmdline, it->first.c_str(), su_dir_path.c_str());
	printf("parasite_implant_su_env err:%s\n", to_string(err).c_str());
	if (is_failed(err)) return;

	// 4.杀光所有历史进程
	for (pid_t pid : pid_arr) { kernel_root::kill_process(ROOT_KEY, pid); }
}

void test_clean_su_env() {
	KRootErr err = kernel_root::uninstall_su(ROOT_KEY);
	printf("uninstall_su err:%s\n", to_string(err).c_str());
}

void test_implant_app(const char* target_pid_cmdline) {
	if (is_failed(kernel_root::get_root(ROOT_KEY))) return;

	// 1.寄生预检目标APP
	std::set<pid_t> pid_arr;
	KRootErr err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, pid_arr);
	if (is_failed(err)) {
		printf("find_all_cmdline_process err:%s\n", to_string(err).c_str());
		return;
	}
	if (pid_arr.size() == 0) {
		printf("请先运行目标APP: %s\n", target_pid_cmdline);
		return;
	}
	std::map<std::string, kernel_root::AppDynlibStatus> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, target_pid_cmdline, so_path_list);
	if (is_failed(err)) {
		printf("parasite_precheck_app err:%s\n", to_string(err).c_str());
		if(err == KRootErr::ERR_EXIST_32BIT) {
			printf("此目标APP为32位应用，无法寄生\n");
		}
		return;
	}
	if (!so_path_list.size()) {
		printf("无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！\n");
		return;
	}
	printf("请在以下的目标APP文件列表中选择一个即将要被寄生的文件:\n");

	std::vector<std::tuple<std::string, kernel_root::AppDynlibStatus>> sort_printf;
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::Running) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
	for (const auto& item : so_path_list) {
		if(item.second != kernel_root::AppDynlibStatus::NotRunning) {
			continue;
		}
		sort_printf.push_back({item.first, item.second});
	}
		for (const auto& item : sort_printf) {
		auto file_path = std::get<0>(item);
		auto app_so_status = std::get<1>(item);
		std::filesystem::path filePath(file_path);
		std::string file_name = filePath.filename().string();
		std::string status = app_so_status == kernel_root::AppDynlibStatus::Running ? "(正在运行)" : "(未运行)";
		if(app_so_status == kernel_root::AppDynlibStatus::Running) {
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
	printf("parasite_implant_app err:%s\n", to_string(err).c_str());
	if (is_failed(err)) return;

	// 3.杀光所有历史进程
	for (pid_t pid : pid_arr) kernel_root::kill_process(ROOT_KEY, pid);
}

int main(int argc, char* argv[]) {
	printf(
		"=======================================\n"
		"本工具名称: SKRoot(Lite) - Linux内核级完美隐藏ROOT演示\n\n"
		"本工具功能列表：\n"

		"1. 测试ROOT权限\n"
		"\tUsage: testRoot test\n\n"

		"2. 执行ROOT命令\n"
		"\tUsage: testRoot cmd <command>\n\n"

		"3. 以ROOT身份直接执行程序\n"
		"\tUsage: testRoot exec <file-path>\n\n"

		"4. 安装部署su\n"
		"\tUsage: testRoot su\n\n"

		"5. 临时注入su到指定进程\n"
		"\tUsage: testRoot suTemp <process-name>\n\n"

		"6. 永久注入su到指定进程\n"
		"\tUsage: testRoot suForever <process-name>\n\n"

		"7. 完全卸载清理su\n"
		"\tUsage: testRoot cleansu\n\n"

		"8. 寄生目标APP\n"
		"\tUsage: testRoot implantApp <process-name>\n\n"

		"本工具特点：\n"
		"新一代 SkRoot，完美隐藏Root功能，兼容安卓 APP 直接JNI调用，稳定不闪退。\n"
		"------------------------------------------------------\n"
		"如需帮助，请使用对应的命令，或者查看上面的菜单。\n\n");
	++argv;
	--argc;
	if (argc < 1) {
		std::cout << "error param." << std::endl;
		return 0;
	}

	//TODO: 在此修改你的Root key值。
	strncpy(ROOT_KEY, "bhuvsUdRKoCLH3OBz6lZeeYYbdsjmRwHc5LDzVPr4LOrq0Uq", sizeof(ROOT_KEY) - 1);

	std::map<std::string, std::function<void()>> command_map = {
		{"test", []() { test_root(); }},
		{"cmd", [argc, argv]() { test_run_root_cmd(argc - 1, argv + 1); }},
		{"exec", [argc, argv]() { test_root_exec_process(argc - 1, argv + 1); }},
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