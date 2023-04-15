#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <sys/capability.h>

#include "../../../../../testRoot/testRoot.h"
#include "../../../../../testRoot/kernel_root_helper.h"
#include "../../../../../testRoot/process64_inject.h"
#include "../../../../../testRoot/init64_process_helper.h"
#include "../../../../../testRoot/su_install_helper.h"

using namespace std;

std::string g_last_su_full_path;

string getCapabilityInfo()
{
    __uid_t now_uid, now_euid, now_suid;
    if (getresuid(&now_uid, &now_euid, &now_suid)) {
        return "FAILED getresuid()";
    }


    __gid_t now_gid, now_egid, now_sgid;
    if (getresgid(&now_gid, &now_egid, &now_sgid)) {
        return "FAILED getresgid()";
    }

    stringstream sstrCapInfo;
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
    sstrCapInfo << "cap effective:" << hex <<cap_data->effective << "," << std::endl
    <<"cap permitted:"<< hex << cap_data->permitted<< "," << std::endl
    <<"cap inheritable:"<< hex <<cap_data->inheritable<< std::endl;
    FILE * fp = popen("getenforce", "r");
    if (fp)
    {
        char cmd[512] = { 0 };
        fread(cmd, 1, sizeof(cmd), fp);
        pclose(fp);

        sstrCapInfo<< "read system SELinux status:"<< cmd;
    }

    return sstrCapInfo.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_testRoot(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    std::string result;
    fork_pipe_info finfo;
    ssize_t err = 0;
    if(fork_pipe_child_process(finfo)) {
        err = kernel_root::get_root(strRootKey.c_str());
        result = "getRoot:";
        result += std::to_string(err);
        result += "\n\n";
        if(err == 0) {
            result += getCapabilityInfo();
            result += "\n\n";
        }
        write_errcode_to_father(finfo, err);
        write_string_to_father(finfo, result);
        _exit(0);
        return 0;
    }
    err = 0;
    if(!wait_fork_child_process(finfo)) {
        err = -1120001;
    } else {
        if(!read_errcode_from_child(finfo, err)) {
            err = -1120002;
        } else if(!read_string_from_child(finfo, result)) {
            err = -1120003;
        }
    }
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runRootCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);


    ssize_t  err;
    string result = kernel_root::run_root_cmd(strRootKey.c_str(), strCmd.c_str(), err);
    stringstream sstr;
    sstr << "runRootCmd err:" << err << ", result:" << result;
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runInit64ProcessCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);


    ssize_t  err;
    string result = safe_run_init64_cmd_wrapper(strRootKey.c_str(), strCmd.c_str(), err);

    stringstream sstr;
    sstr << "runInit64Cmd err:" << err << ", result:" << result;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_installSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring basePath,
        jstring originSuFullPath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(basePath, 0);
    string strBasePath= str1;
    env->ReleaseStringUTFChars(basePath, str1);

    str1 = env->GetStringUTFChars(originSuFullPath, 0);
    string strOriginSuFullPath= str1;
    env->ReleaseStringUTFChars(originSuFullPath, str1);

    stringstream sstr;
    //安装su工具套件
    ssize_t err;
    std::string su_hide_full_path = safe_install_su(strRootKey.c_str(), strBasePath.c_str(), strOriginSuFullPath.c_str(), err);
    sstr << "install su err:" << err<<", su_hide_full_path:" << su_hide_full_path << std::endl;
    g_last_su_full_path = su_hide_full_path;
    if (err == 0) {
        sstr << "installSu done."<< std::endl;
    }
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getLastInstallSuFullPath(
        JNIEnv* env,
        jobject /* this */) {
    return env->NewStringUTF(g_last_su_full_path.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_uninstallSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring basePath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(basePath, 0);
    string strBasePath= str1;
    env->ReleaseStringUTFChars(basePath, str1);

    stringstream sstr;

    ssize_t err = safe_uninstall_su(strRootKey.c_str(), strBasePath.c_str());
    sstr << "uninstallSu err:" << err << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    g_last_su_full_path.clear();
    sstr << "uninstallSu done.";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_autoSuEnvInject(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {
    
    if(g_last_su_full_path.empty()) {
        return env->NewStringUTF("【错误】请先安装部署su");
    }
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    stringstream sstr;

    //杀光所有历史进程
    std::vector<pid_t> vOut;
    ssize_t err = safe_find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), vOut);
    sstr << "find_all_cmdline_process err:"<< err<<", cnt:"<<vOut.size() << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    std::string kill_cmd;
    for (pid_t t : vOut) {
        err =  safe_kill_process(strRootKey.c_str(), t);
        sstr << "kill_ret err:"<< err << std::endl;
        if (err != 0) {
            return env->NewStringUTF(sstr.str().c_str());
        }
    }
    pid_t pid;
    err = safe_wait_and_find_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), 60*1000, pid);

    std::string folder_path = g_last_su_full_path;
    int n = folder_path.find_last_of("/");
    if(n != -1) {
        folder_path = folder_path.substr(0,n);
    }
    sstr << "autoSuEnvInject("<< err<<", " <<  folder_path <<")" << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    err = safe_inject_process_env64_PATH_wrapper(strRootKey.c_str(), pid, folder_path.c_str());
    sstr << "autoSuEnvInject ret val:" << err << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "autoSuEnvInject done.";
    return env->NewStringUTF(sstr.str().c_str());
}
