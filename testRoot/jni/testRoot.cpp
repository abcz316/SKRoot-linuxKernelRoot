#include "testRoot.h"

// TODO：请将此处的KEY替换为你的内核ROOT KEY
#define ROOT_KEY "OM4kKoPVGFG2tnVFcs1PJ1qp6HtVymjV0CoTgFDmMdSDALve"

namespace {
constexpr const char* k_su_base_path = "/data/local/tmp";
}
void test_root() {
	// 获取ROOT权限
	printf("%s\n", get_capability_info().c_str());

	printf("get_root ret:%zd\n", kernel_root::get_root(ROOT_KEY));

	printf("%s\n", get_capability_info().c_str());
	return;
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

void test_su_env_inject(const char* target_pid_cmdline) {
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

void test_clean_su_env() {
	// 完全卸载清理su
	ssize_t err = kernel_root::uninstall_su(ROOT_KEY, k_su_base_path, "su");
	printf("uninstall_su err:%zd\n", err);
}

void test_implant_app(const char* target_pid_cmdline) {
	// 1.寄生预检目标APP
	std::set<pid_t> out;
	ssize_t err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, out);
	if (err) {
		printf("find_all_cmdline_process err:%zd\n", err);
		return;
	}
	if (out.size() == 0) {
		printf("请先运行目标APP: %s\n", target_pid_cmdline);
		return;
	}
	std::set<std::string> so_path_list;
	err = kernel_root::parasite_precheck_app(ROOT_KEY, target_pid_cmdline, so_path_list);
	if (err) {
		printf("parasite_precheck_app error:%zd\n", err);
		if(err == -9903) {
			printf("此目标APP为32位应用，无法寄生\n");
		}
		return;
	}
	if (!so_path_list.size()) {
		printf("无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试\n");
		return;
	}
	printf("请在以下的目标APP文件列表中选择一个即将要被寄生的文件:\n");
	for (const std::string& item : so_path_list) {
		std::filesystem::path filePath(item);
		printf("\t%s\n", filePath.filename().string().c_str());
	}
	printf("\n");
	printf("请输入将要被寄生的文件名称: ");
	std::string user_input_so_name;
	std::getline(std::cin, user_input_so_name);
	printf("\n");
	auto it = std::find_if(so_path_list.begin(), so_path_list.end(), 
        [&](const std::string& s) { return s.find(user_input_so_name) != std::string::npos; });
    if (it == so_path_list.end()) {
		printf("Not found: %s\n", user_input_so_name.c_str());
		return;
    }
	
	// 2.寄生植入目标APP
	err = kernel_root::parasite_implant_app(ROOT_KEY, target_pid_cmdline, it->c_str());
	printf("parasite_implant_app err:%zd\n", err);
	if(err) { return; }

	// 3.杀光所有历史进程
	for (pid_t pid : out) { kernel_root::kill_process(ROOT_KEY, pid); }
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

		"6. 注入su到指定进程\n"
		"\tUsage: testRoot process <process-name>\n\n"

		"7. 完全卸载清理su\n"
		"\tUsage: testRoot cleansu\n\n"

		"8. 寄生目标APP\n"
		"\tUsage: testRoot implantApp <process-name> [so-name]\n\n"

		"本工具特点：\n"
		"新一代SKRoot，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，兼容安卓APP直接JNI稳定调用。\n"
		"======================================================\n"
		"为了实现最佳的隐蔽性，推荐使用 [寄生目标APP] 功能，即将此工具寄生到能常驻后台的APP上\n\n"
		"如需帮助，请使用对应的命令，或者查看上面的菜单。\n\n");

	++argv;
	--argc;
	if (argc == 0 || strcmp(argv[0], "id") == 0) { // 1.显示自身权限信息
		printf("%s\n", get_capability_info().c_str());
	} else if (strcmp(argv[0], "get") == 0) { // 2.获取ROOT权限
		test_root();
	} else if (argc >= 2 && strcmp(argv[0], "cmd") == 0) { // 3.执行ROOT命令
		test_run_root_cmd(argc - 1, argv + 1);
	} else if (argc >= 2 && strcmp(argv[0], "init") == 0) { // 4.执行原生内核命令
		test_run_init64_cmd(argc - 1, argv + 1);
	} else if (strcmp(argv[0], "su") == 0) { // 5.安装部署su
		test_install_su_env();
	} else if (argc > 1 && strcmp(argv[0], "process") == 0) { // 6.注入su到指定进程
		test_su_env_inject(argv[1]);
	} else if (strcmp(argv[0], "cleansu") == 0) { // 7.完全卸载清理su
		test_clean_su_env();
	} else if (argc > 1 && strcmp(argv[0], "implantApp") == 0) { // 8.寄生目标APP
		test_implant_app(argv[1]);
	} else {
		printf("unknown command.\n");
		return 1;
	}
	return 0;
}