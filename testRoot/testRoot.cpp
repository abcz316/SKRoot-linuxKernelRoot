#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <vector>
#include <sstream>
#include <thread>
#include <sys/capability.h>
#include "kernel_root_kit/kernel_root_kit_umbrella.h"
#include "../su/su_hide_path_utils.h"

#define ROOT_KEY "OM4kKoPVGFG2tnVFcs1PJ1qp6HtVymjV0CoTgFDmMdSDALve"

std::string get_executable_directory() {
    char processdir[4096] = {0}; // Consider using PATH_MAX from limits.h
    ssize_t path_len = readlink("/proc/self/exe", processdir, sizeof(processdir));
    if(path_len > 0) {
		char* path_end = strrchr(processdir, '/');
		if(path_end) {
			*path_end = '\0';
			return std::string(processdir);
		}
	}
    return {};
}

void show_capability_info() {
	printf("Current process information:\n");
	__uid_t now_uid, now_euid, now_suid;
	if (getresuid(&now_uid, &now_euid, &now_suid)) {
		perror("FAILED getresuid()");
		return;
	}


	__gid_t now_gid, now_egid, now_sgid;
	if (getresgid(&now_gid, &now_egid, &now_sgid)) {
		perror("FAILED getresgid()");
		return;
	}

	printf("uid=%d, euid=%d, suid=%d, gid=%d, egid=%d, sgid=%d\n",
		now_uid, now_euid, now_suid,
		now_gid, now_egid, now_sgid);


	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = &cap_header_data;

	struct __user_cap_data_struct cap_data_data;
	cap_user_data_t cap_data = &cap_data_data;

	cap_header->pid = getpid();
	cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3
	if (capget(cap_header, cap_data) < 0) {
		perror("FAILED capget()");
		return;
	}

	printf("cap effective:0x%x, cap permitted:0x%x, cap inheritable:0x%x\n", cap_data->effective, cap_data->permitted, cap_data->inheritable);
	printf("native check SELinux status: %d\n", kernel_root::is_enable_selinux() ? 1 : 0);

	FILE* fp = popen("getenforce", "r");
	if (fp) {
		char shell[512] = { 0 };
		fread(shell, 1, sizeof(shell), fp);
		pclose(fp);
		printf("read system SELinux status: %s\n", shell);
	}
}
void test_root() {
	show_capability_info();

	printf("get_root ret:%zd\n", kernel_root::get_root(ROOT_KEY));

	show_capability_info();

	//system("id");
	//system("/data/local/tmp/getmyinfo");
	//system("insmod /sdcard/rwProcMem37.ko ; echo $?");
	//system("cat /proc/1/maps");
	//system("ls /proc");
	//system("screencap -p /sdcard/temp.png");
	return;
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

	ssize_t err;
	std::string result = kernel_root::run_root_cmd(ROOT_KEY, sstrCmd.str().c_str(), err);
	printf("test_run_root_cmd err:%zd\n", err);
	printf("test_run_root_cmd result:%s\n", result.c_str());
}

void test_run_init64_cmd(int argc, char* argv[]) {
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
	std::string myself_path = get_executable_directory();

	//1.安装su工具套件
	ssize_t err;
	std::string su_hide_full_path = kernel_root::install_su(ROOT_KEY, myself_path.c_str(), std::string(myself_path + std::string("/su")).c_str(), err);
	printf("install su hide full path:%s, err:%zd\n", su_hide_full_path.c_str(), err);
}

void test_su_env_inject(const char* target_pid_cmdline) {
	std::string myself_path = get_executable_directory();
	if (kernel_root::get_root(ROOT_KEY) != 0) {
		return;
	}
	
	//1.获取su_xxx隐藏目录
	std::string su_hide_path = kernel_root::find_su_hide_folder_path(myself_path.c_str(), "su");
	printf("su_hide_path ret val:%s\n", su_hide_path.c_str());
	if (su_hide_path.empty()) {
		return;
	}

	//2.杀光所有历史进程
	std::vector<pid_t> vOut;
	ssize_t err = kernel_root::find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, vOut);
	printf("find_all_cmdline_process err:%zd, cnt:%zu\n", err, vOut.size());
	if (err != 0) {
		return;
	}
	for (pid_t pid : vOut) {
		err = kernel_root::kill_process(ROOT_KEY, pid);
		printf("kill err:%zd\n", err);
		if (err != 0) {
			return;
		}
	}

	//3.注入su环境变量到指定进程
	printf("test_auto_su_env_inject Waiting for process creation(%s)\n", target_pid_cmdline);
	pid_t pid;
	err = kernel_root::wait_and_find_cmdline_process(ROOT_KEY, target_pid_cmdline, 60 * 1000, pid);
	printf("test_auto_su_env_inject(%zd)\n", err);

	err = kernel_root::inject_process_env64_PATH_wrapper(ROOT_KEY, pid, su_hide_path.c_str());
	printf("test_auto_su_env_inject ret val:%zd, error:%s\n", err, strerror(errno));
}

void test_clean_su_env() {
	std::string myself_path = get_executable_directory();

	ssize_t err = kernel_root::uninstall_su(ROOT_KEY, myself_path.c_str(), "su");
	printf("uninstall_su err:%zd\n", err);
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
		
		"本工具特点：\n"
		"新一代SKRoot，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，兼容安卓APP直接JNI稳定调用。\n"
		"======================================================\n"
		"如需帮助，请使用对应的命令，或者查看上面的菜单。\n"
	);

	++argv;
	--argc;
	if (argc == 0 || strcmp(argv[0], "id") == 0) { //1.显示自身权限信息
		show_capability_info();
	} else if (strcmp(argv[0], "get") == 0) { //2.获取ROOT权限
		test_root();
	} else if (argc >= 2 && strcmp(argv[0], "cmd") == 0) { //3.执行ROOT命令
		test_run_root_cmd(argc - 1, argv + 1);
	} else if (argc >= 2 && strcmp(argv[0], "init") == 0) { //4.执行原生内核命令
		test_run_init64_cmd(argc - 1, argv + 1);
	} else if (strcmp(argv[0], "su") == 0) { //5.安装部署su
		test_install_su_env();
	} else if (argc > 1 && strcmp(argv[0], "process") == 0) { //6.注入su到指定进程
		test_su_env_inject(argv[1]);
	} else if (strcmp(argv[0], "cleansu") == 0) { //7.完全卸载清理su
		test_clean_su_env();
	} else {
		printf("unknown command.\n");
		return 1;
	}
	return 0;
}