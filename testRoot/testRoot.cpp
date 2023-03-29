#include "testRoot.h"
#include <sstream>
#include <thread>
#include <sys/capability.h>
#include "kernel_root_helper.h"
#include "kernel_root_key.h"
#include "process64_inject.h"
#include "process_cmdline_utils.h"
#include "init64_process_helper.h"
#include "su_install_helper.h"
#include "myself_path_utils.h"
#include "../su/su_hide_path_utils.h"

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
	printf("native check SELinux status: %d\n", kernel_root::is_disable_selinux_status() ? 0 : 1);

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

void test_run_root_cmd(const char* shell) {
	printf("test_run_root_cmd(%s)\n", shell);

	ssize_t err;
	std::string result = kernel_root::run_root_cmd(ROOT_KEY, shell, err);
	printf("test_run_root_cmd err:%zd\n", err);
	printf("test_run_root_cmd result:%s\n", result.c_str());
}
void test_run_init64_cmd(const char* cmd) {
	printf("test_run_init64_cmd(%s)\n", cmd);

	ssize_t err;
	std::string result = run_init64_cmd_wrapper(ROOT_KEY, cmd, err);
	printf("run_init64_cmd_wrapper err:%zd\n", err);
	printf("run_init64_cmd_wrapper result:%s\n", result.c_str());
}

void test_install_su_env() {
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);

	//1.安装su工具套件
	ssize_t err;
	std::string su_hide_full_path = install_su(ROOT_KEY, myself_path,  std::string(myself_path + std::string("/su")).c_str(), err);
	printf("install su hide full path:%s, err:%zd\n", su_hide_full_path.c_str(), err);
}

void test_su_env_inject(const char* target_pid_cmdline) {
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);

	if (kernel_root::get_root(ROOT_KEY) != 0) {
		return;
	}
	
	//1.获取su_xxx隐藏目录
	std::string su_hide_path = find_su_hide_folder_path(myself_path, "su");
	printf("su_hide_path ret val:%s\n", su_hide_path.c_str());
	if (su_hide_path.empty()) {
		return;
	}

	//2.杀光所有历史进程
	std::vector<pid_t> vOut;
	ssize_t err = find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, vOut);
	printf("find_all_cmdline_process err:%zd, cnt:%zu\n", err, vOut.size());
	if (err != 0) {
		return;
	}
	for (pid_t pid : vOut) {
		err = kill_process(ROOT_KEY, pid);
		printf("kill err:%zd\n", err);
		if (err != 0) {
			return;
		}
	}

	//3.注入su环境变量到指定进程
	printf("test_auto_su_env_inject Waiting for process creation(%s)\n", target_pid_cmdline);
	pid_t pid;
	err = wait_and_find_cmdline_process(ROOT_KEY, target_pid_cmdline, 60 * 1000, pid);
	printf("test_auto_su_env_inject(%zd)\n", err);

	err = inject_process_env64_PATH_wrapper(ROOT_KEY, pid, su_hide_path.c_str());
	printf("test_auto_su_env_inject ret val:%zd, error:%s\n", err, strerror(errno));
}

void test_clean_su_env() {
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);

	ssize_t err = uninstall_su(ROOT_KEY, myself_path, "su");
	printf("uninstall_su err:%zd\n", err);
}
int main(int argc, char* argv[]) {
	printf(
		"======================================================\n"
		"本工具名称: SKRoot - Linux 完美内核级隐藏ROOT演示\n"
		"本工具功能列表：\n"
		"\t1.显示自身权限信息\n"
		"\t2.获取ROOT权限\n"
		"\t3.执行ROOT命令\n"
		"\t4.执行原生内核命令\n"
		"\t5.安装部署隐藏版su\n"
		"\t6.注入su到指定进程\n"
		"\t7.完全卸载清理su\n"
		"\t新一代SKRoot，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，兼容安卓APP直接JNI稳定调用。\n"
		"======================================================\n"
	);

	++argv;
	--argc;
	if (argc == 0 || strcmp(argv[0], "id") == 0) { //1.显示自身权限信息
		show_capability_info();
	} else if (strcmp(argv[0], "get") == 0) { //2.获取ROOT权限
		test_root();
	} else if (argc >= 2 && strcmp(argv[0], "cmd") == 0) { //3.执行ROOT命令
		std::stringstream sstrCmd;
		for (int i = 1; i < argc; i++) {
			sstrCmd << argv[i];
			if (i != (argc - 1)) {
				sstrCmd << " ";
			}
		}
		test_run_root_cmd((char*)sstrCmd.str().c_str());
	} else if (argc >= 2 && strcmp(argv[0], "init") == 0) { //4.执行原生内核命令
		std::stringstream sstrCmd;
		for (int i = 1; i < argc; i++) {
			sstrCmd << argv[i];
			if (i != argc) {
				sstrCmd << " ";
			}
		}
		test_run_init64_cmd((char*)sstrCmd.str().c_str());
	} else if (strcmp(argv[0], "su") == 0) { //5.安装部署隐藏版su
		test_install_su_env();
	} else if (argc > 1 && strcmp(argv[0], "process") == 0) { //6.注入su到指定进程
		std::stringstream sstrCmd;
		sstrCmd << argv[1];
		if (sstrCmd.str().length()) {
			test_su_env_inject(sstrCmd.str().c_str());
		}
	} else if (strcmp(argv[0], "cleansu") == 0) { //7.完全卸载清理su
		test_clean_su_env();
	} else {
		printf("unknown command.\n");
		return 1;
	}
	return 0;
}