#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <sys/capability.h>

#include "../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_umbrella.h"
#include "../../../../../testRoot/jni/testRoot.h"
#include "urlEncodeUtils.h"
using namespace std;

std::string g_last_su_full_path;

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_testRoot(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    std::string result;
    kernel_root::fork_pipe_info finfo;
    ssize_t err = 0;
    if(fork_pipe_child_process(finfo)) {
        err = kernel_root::get_root(strRootKey.c_str());
        result = "getRoot:";
        result += std::to_string(err);
        result += "\n\n";
        if(err == 0) {
            result += get_capability_info();
            result += "\n\n";
        }
        write_errcode_from_child(finfo, err);
        write_string_from_child(finfo, result);
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
    string result = kernel_root::safe_run_init64_cmd_wrapper(strRootKey.c_str(), strCmd.c_str(), err);

    stringstream sstr;
    sstr << "runInit64Cmd err:" << err << ", result:" << result;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_installSu(
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
    //安装su工具套件
    ssize_t err;
    std::string su_hide_full_path = kernel_root::safe_install_su(strRootKey.c_str(), strBasePath.c_str(), err);
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

    ssize_t err = kernel_root::safe_uninstall_su(strRootKey.c_str(), strBasePath.c_str());
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
    std::set<pid_t> out;
    ssize_t err = kernel_root::safe_find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), out);
    sstr << "find_all_cmdline_process err:"<< err<<", cnt:"<<out.size() << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    std::string kill_cmd;
    for (pid_t t : out) {
        err =  kernel_root::safe_kill_process(strRootKey.c_str(), t);
        sstr << "kill_ret err:"<< err << std::endl;
        if (err != 0) {
            return env->NewStringUTF(sstr.str().c_str());
        }
    }
    pid_t pid;
    err = kernel_root::safe_wait_and_find_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), 60*1000, pid);

    std::string folder_path = g_last_su_full_path;
    int n = folder_path.find_last_of("/");
    if(n != -1) {
        folder_path = folder_path.substr(0,n);
    }
    sstr << "autoSuEnvInject("<< err<<", " <<  folder_path <<")" << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    err = kernel_root::safe_inject_process_env64_PATH_wrapper(strRootKey.c_str(), pid, folder_path.c_str());
    sstr << "autoSuEnvInject ret val:" << err << std::endl;
    if (err != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "autoSuEnvInject done.";
    return env->NewStringUTF(sstr.str().c_str());
}



extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getAllCmdlineProcess(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    std::stringstream ss;

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    std::string strRootKey = str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    std::map<pid_t, std::string> pid_map;
    ssize_t err = kernel_root::safe_get_all_cmdline_process(strRootKey.c_str(), pid_map);
    if(err != 0) {
        ss << "get_all_cmdline_process err:"<< err<< std::endl;
        return env->NewStringUTF(ss.str().c_str());
    }

    ss << "{\"data\":[";
    for (auto iter = pid_map.begin(); iter != pid_map.end(); ) {
        size_t len = iter->second.length();
        size_t max_encoded_len = 3 * len + 1;
        shared_ptr<char> spData(new (std::nothrow) char[max_encoded_len], std::default_delete<char[]>());
        memset(spData.get(), 0, max_encoded_len);
        url_encode(const_cast<char*>(iter->second.c_str()), spData.get());
        ss << "{\"" << iter->first << "\":\"" << spData.get() << "\"}";
        if (++iter != pid_map.end()) {
            ss << ",";
        }
    }
    ss << "]}";
    return env->NewStringUTF(ss.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_parasitePrecheckApp(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    stringstream sstr;
    std::set<pid_t> test_pid;
    ssize_t err = kernel_root::safe_find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), test_pid);
    if (err != 0) {
        sstr << "find_all_cmdline_process err:"<< err<<", cnt:"<< test_pid.size() << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    if (test_pid.size() == 0) {
        sstr << "目标进程不存在" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    std::set<std::string> so_path_list;
    err = kernel_root::safe_parasite_precheck_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), so_path_list);
    if (err) {
        sstr << "parasite_precheck_app ret val:" << err << std::endl;
        if(err == -9903) {
            sstr << "此目标APP为32位应用，无法寄生" << err << std::endl;
        }
        return env->NewStringUTF(sstr.str().c_str());
    }

    if (!so_path_list.size()) {
        sstr << "目标APP无法寄生：无法检测到目标APP的JNI环境，您可尝试重启目标APP后再试" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    sstr << "{\"soPaths\":[";
    for (auto iter = so_path_list.begin(); iter != so_path_list.end(); ) {
        size_t len = iter->length();
        size_t max_encoded_len = 3 * len + 1;
        std::shared_ptr<char> spData(new (std::nothrow) char[max_encoded_len], std::default_delete<char[]>());
        memset(spData.get(), 0, max_encoded_len);
        url_encode(const_cast<char*>(iter->c_str()), spData.get());
        sstr << "\"" << spData.get() << "\"";
        if (++iter != so_path_list.end()) {
            sstr << ",";
        }
    }
    sstr << "]}";
    return env->NewStringUTF(sstr.str().c_str());

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_parasiteImplantApp(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring targetSoFullPath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    str1 = env->GetStringUTFChars(targetSoFullPath, 0);
    string strTargetSoFullPath = str1;
    env->ReleaseStringUTFChars(targetSoFullPath, str1);

    stringstream sstr;
    ssize_t err = kernel_root::safe_parasite_implant_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), strTargetSoFullPath.c_str());
    if (err != 0) {
        sstr << "parasite_implant_app err:"<< err << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "parasiteImplantApp done.";
    return env->NewStringUTF(sstr.str().c_str());

}

