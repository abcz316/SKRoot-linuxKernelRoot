#include <string.h>
#include <unistd.h>
#include <sstream>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "command.h"
#include "fork_helper.h"

struct caps_info {
    uint64_t inheritable = 0;
    uint64_t permitted = 0;
    uint64_t effective = 0;
    uint64_t bounding = 0;
    uint64_t ambient = 0;
};

static inline __uid_t my_getfsuid() {
    return syscall(SYS_setfsuid, (uid_t)-1);
}

static inline __gid_t my_getfsgid() {
    return syscall(SYS_setfsgid, (gid_t)-1);
}

static bool get_self_caps(caps_info& out) {
    memset(&out, 0, sizeof(out));

    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return false;

    const char* KEY_INH = "CapInh:";
    const char* KEY_PRM = "CapPrm:";
    const char* KEY_EFF = "CapEff:";
    const char* KEY_BND = "CapBnd:";
    const char* KEY_AMB = "CapAmb:";

    char line[256];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        char key[32] = {0};
        char hexv[65] = {0};
        if (sscanf(line, "%31s %64s", key, hexv) != 2) continue;

        errno = 0;
        char* endp = nullptr;
        unsigned long long v = strtoull(hexv, &endp, 16);
        if (errno != 0 || endp == hexv) continue;

        if (strcmp(key, KEY_INH) == 0) { out.inheritable = v; ++found; }
        else if (strcmp(key, KEY_PRM) == 0) { out.permitted = v; ++found; }
        else if (strcmp(key, KEY_EFF) == 0) { out.effective = v; ++found; }
        else if (strcmp(key, KEY_BND) == 0) { out.bounding = v; ++found; }
        else if (strcmp(key, KEY_AMB) == 0) { out.ambient = v; ++found; }
    }

    fclose(fp);
    return found >= 0;
}

static std::string print_self_uid_caps_state() {
    std::ostringstream oss;

    __uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        perror("getresuid failed");
        return "getresuid failed\n";
    }
    __gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) {
        perror("getresgid failed");
        return "getresgid failed\n";
    }
    __uid_t fsuid = my_getfsuid();
    __gid_t fsgid = my_getfsgid();

    oss << "current process status:\n";
    oss << "ruid: " << ruid << "\n";
    oss << "rgid: " << rgid << "\n";
    oss << "suid: " << suid << "\n";
    oss << "sgid: " << sgid << "\n";
    oss << "euid: " << euid << "\n";
    oss << "egid: " << egid << "\n";
    oss << "fsuid: " << fsuid << "\n";
    oss << "fsgid: " << fsgid << "\n";

    caps_info caps;
    get_self_caps(caps);
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    int securebits = prctl(PR_GET_SECUREBITS);

    oss << "capInh: 0x" << std::hex << caps.inheritable << std::dec << "\n";
    oss << "capPrm: 0x" << std::hex << caps.permitted   << std::dec << "\n";
    oss << "capEff: 0x" << std::hex << caps.effective   << std::dec << "\n";
    oss << "capBnd: 0x" << std::hex << caps.bounding    << std::dec << "\n";
    oss << "capAmb: 0x" << std::hex << caps.ambient     << std::dec << "\n";
    oss << "seccomp: " << seccomp << "\n";
    oss << "securebits: " << securebits << "\n";

    FILE *fp = popen("getenforce", "r");
    if (fp) {
        char cmd[512];
        size_t n = fread(cmd, 1, sizeof(cmd) - 1, fp);
        pclose(fp);

        cmd[n] = '\0';
        if (n > 0 && cmd[n - 1] == '\n') cmd[--n] = '\0';

        oss << "selinux: " << cmd << "\n";
    }

    return oss.str();
}

inline std::string print_proc_self_cgroup(const char* tag = nullptr) {
    std::string cg = "cgroup:\n";
    int f = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    if (f >= 0) {
        for (;;) {
            char buf[1024] = {0};
            ssize_t r = read(f, buf, sizeof(buf));
            if (r > 0) cg.append(buf, buf + r);
            else if (r == -1 && errno == EINTR) continue;
            else break;
        }
        close(f);
    } else {
        cg += "(unreadable)\n";
    }
    return cg;
}

static bool unsafe_test_root(const char* str_root_key, std::string& out) {
	if(!get_root(str_root_key)) return false;
    out = print_self_uid_caps_state();
    out += "===================\n";
    out += print_proc_self_cgroup();
	return true;
}

static bool safe_test_root(const char* str_root_key, std::string& out) {
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
        std::string info;
		bool ret = unsafe_test_root(str_root_key, info);
		write_bool_from_child(finfo, ret);
		write_string_from_child(finfo, info);
        finfo.close_all();
		_exit(0);
		return true;
	}
	bool success = true;
    if(!read_bool_from_child(finfo, success)) success = false;
    else if(!read_string_from_child(finfo, out)) success = false;
    int status = 0; waitpid(finfo.child_pid, &status, 0);
	return success;
}

const char* get_root_test_report(const char* str_root_key) {
    static thread_local std::string report;
    report.clear();
    std::string result;
    bool success = safe_test_root(str_root_key, result);
    report = "get_root: ";
    report += success ? "OK" : "FAILED";
    report += + "\n\n" + result + "\n";
    return report.c_str();
}