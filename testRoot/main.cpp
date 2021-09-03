#include <cstdio>
#include <sys/capability.h>

#include "super_root.h"
#include "adb_inject.h"
#define ROOT_KEY 0x7F6766F8

void show_capability_info()
{
	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = &cap_header_data;

	struct __user_cap_data_struct cap_data_data;
	cap_user_data_t cap_data = &cap_data_data;

	cap_header->pid = getpid();
	cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3

	if (capget(cap_header, cap_data) < 0) {
		perror("FAILED capget()");
		exit(1);
	}

	printf("Cap data 0x%x, 0x%x, 0x%x\n", cap_data->effective, cap_data->permitted, cap_data->inheritable);
	printf("now getuid()=%d,geteuid()=%d,getgid()=%d,getegid()=%d\n", getuid(), geteuid(), getgid(), getegid());

	FILE * fp = popen("getenforce", "r");
	if (fp)
	{
		char cmd[512] = { 0 };
		fread(cmd, 1, sizeof(cmd), fp);
		pclose(fp);

		printf("SELinux status: %s\n", cmd);
	}
}
void test_root()
{
	show_capability_info();

	printf("get_root ret:%d\n", get_root(ROOT_KEY));

	show_capability_info();

	//system("id");
	//system("/data/local/tmp/getmyinfo");
	//system("insmod /sdcard/rwProcMem37.ko ; echo $?");
	//system("cat /proc/1/maps");
	//system("ls /proc");
	//system("screencap -p /sdcard/temp.png");
	return;
}

void test_disable_selinux()
{
	int ret = disable_selinux(ROOT_KEY);
	printf("disable_selinux ret:%d\n", ret);
	printf("done.\n");
	return;
}

void test_enable_selinux()
{
	int ret = enable_selinux(ROOT_KEY);
	printf("enable_selinux ret:%d\n", ret);
	printf("done.\n");
	return;
}


void test_run_cmd(char * cmd, bool bKeepAdbRoot = false) {
	printf("inject_cmd_remote_process(%s)\n", cmd);
	char szResult[0x1000] = { 0 };
	ssize_t ret = safe_inject_adb_process_run_cmd_wrapper(ROOT_KEY, cmd, bKeepAdbRoot, szResult, sizeof(szResult));
	printf("inject_cmd_remote_process ret val:%zd\n", ret);
	printf("inject_cmd_remote_process result:%s\n", szResult);
}

int main(int argc, char *argv[])
{
	printf(
		"======================================================\n"
		"本工具名称: Linux ARM64 完美隐藏ROOT演示\n"
		"本工具功能列表：\n"
		"\t1.显示自身权限信息\n"
		"\t2.获取ROOT权限\n"
		"\t3.绕过SELinux\n"
		"\t4.还原SELinux\n"
		"\t5.执行ROOT权限级别的Shell命令\n"
		"\t6.赋予ADB最高级别权限\n"
		"\t新一代root，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，挑战全网root检测手段，兼容安卓APP直接JNI调用，稳定、流畅、不闪退。\n"
		"======================================================\n"
	);


	++argv;
	--argc;


	int cmdc;
	char *cmdv[6];

	while (argc) {
		// Clean up
		cmdc = 0;
		memset(cmdv, 0, sizeof(cmdv));

		// Split the commands
		for (char *tok = strtok(argv[0], " "); tok; tok = strtok(nullptr, " "))
		{
			cmdv[cmdc++] = tok;
			if (cmdc == 0)
			{
				continue;
			}
		}
			

		if (strcmp(cmdv[0], "show") == 0) {
			show_capability_info();
		}
		else if (strcmp(cmdv[0], "root") == 0) {
			test_root();
		}
		else if (strcmp(cmdv[0], "disable") == 0) {
			test_disable_selinux();
		}
		else if (strcmp(cmdv[0], "enable") == 0) {
			test_enable_selinux();
		}
		else if (strcmp(cmdv[0], "cmd") == 0) {
			test_run_cmd("id");
			//test_run_cmd("id > /sdcard/run.txt");
			//test_run_cmd("insmod rwProcMem37.ko > /sdcard/run.txt");
		}
		else if (strcmp(cmdv[0], "adb") == 0) {
			test_run_cmd("id", true);
		}
		else {
			return 1;
		}

		--argc;
		++argv;
	}
	return 0;
}