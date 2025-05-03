#ifndef _TEST_ROOT_H_
#define _TEST_ROOT_H_
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    FILE *fp = fopen(("/proc/" + std::to_string(getpid()) + "/status").c_str(), "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "CapInh:", 7) == 0 || strncmp(line, "CapPrm:", 7) == 0 || strncmp(line, "CapEff:", 7) == 0
            || strncmp(line, "CapBnd:", 7) == 0 || strncmp(line, "CapAmb:", 7) == 0) {
                sstrCapInfo << line;
            }
        }
        fclose(fp);
    } else {
        sstrCapInfo << "Failed to read /proc/[pid]/status for CapAbility.\n";
    }

    fp = popen("getenforce", "r");
    if (fp) {
        char cmd[512] = { 0 };
        fread(cmd, 1, sizeof(cmd), fp);
        pclose(fp);
        sstrCapInfo<< "read system SELinux status:"<< cmd;
    }
    return sstrCapInfo.str();
}


#endif /* _TEST_ROOT_H_ */
