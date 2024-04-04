#ifndef _TEST_ROOT_H_
#define _TEST_ROOT_H_
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <vector>
#include "kernel_root_kit/kernel_root_kit_umbrella.h"
#include "su/su_hide_path_utils.h"

static std::string get_capability_info() {
    __uid_t now_uid, now_euid, now_suid;
	__gid_t now_gid, now_egid, now_sgid;
    if (getresuid(&now_uid, &now_euid, &now_suid)) {
        return "FAILED getresuid()";
    }
    if (getresgid(&now_gid, &now_egid, &now_sgid)) {
        return "FAILED getresgid()";
    }

    std::stringstream sstrCapInfo;
    sstrCapInfo<< "Current process information:\n";
    sstrCapInfo<< "uid:"<<now_uid <<"," << std::endl <<"euid:"<< now_euid <<"," << std::endl
    <<"suid:"<< now_suid <<"," << std::endl <<"gid:"<< now_gid <<"," << std::endl
    <<"egid:"<< now_egid <<"," << std::endl <<"sgid:"<< now_sgid <<"\n";

    struct __user_cap_header_struct cap_header_data;
    cap_user_header_t cap_header = &cap_header_data;

    struct __user_cap_data_struct cap_data_data;
    cap_user_data_t cap_data = &cap_data_data;

    cap_header->pid = getpid();
    cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3

    if (capget(cap_header, cap_data) < 0) {
        return "FAILED capget()";
        // perror("FAILED capget()");
        //exit(1);
    }
    sstrCapInfo << "cap effective:" << std::hex <<cap_data->effective << "," << std::endl
    <<"cap permitted:"<< std::hex << cap_data->permitted<< "," << std::endl
    <<"cap inheritable:"<< std::hex <<cap_data->inheritable<< std::endl;
    FILE * fp = popen("getenforce", "r");
    if (fp) {
        char cmd[512] = { 0 };
        fread(cmd, 1, sizeof(cmd), fp);
        pclose(fp);
        sstrCapInfo<< "read system SELinux status:"<< cmd;
    }
    return sstrCapInfo.str();
}


#endif /* _TEST_ROOT_H_ */
