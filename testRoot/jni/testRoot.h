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

#include <sys/syscall.h>

#include "kernel_root_kit/kernel_root_kit_umbrella.h"
#include "su/su_hide_path_utils.h"


static inline __uid_t my_getfsuid() {
    return syscall(SYS_setfsuid, (uid_t)-1);
}

static inline __gid_t my_getfsgid() {
    return syscall(SYS_setfsgid, (gid_t)-1);
}

static std::string get_capability_info() {
    __uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        return "FAILED getresuid()";
    }
    __gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) {
        return "FAILED getresgid()";
    }
    __uid_t fsuid = my_getfsuid();
    __gid_t fsgid = my_getfsgid();

    std::stringstream sstrCapInfo;
    sstrCapInfo << "Current process identity info:\n"
        << "ruid: " << ruid  << "\n"
        << "rgid: " << rgid  << "\n"
        << "suid: " << suid  << "\n"
        << "sgid: " << sgid  << "\n"
        << "euid: " << euid  << "\n"
        << "egid: " << egid  << "\n"
        << "fsuid: " << fsuid << "\n"
        << "fsgid: " << fsgid << "\n";

    long sb = prctl(PR_GET_SECUREBITS);
    sstrCapInfo<< "securebits: " << (void*)sb <<"\n";

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
