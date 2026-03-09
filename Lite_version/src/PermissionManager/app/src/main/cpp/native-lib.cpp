#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <filesystem>
#include <sys/capability.h>

#include "kernel_root_kit/include/rootkit_umbrella.h"
#include "urlEncodeUtils.h"
#include "cJSON.h"
using namespace std;

std::string g_last_su_file_path;

static string jstringToStr(JNIEnv* env, jstring jstring1) {
    const char *str1 = env->GetStringUTFChars(jstring1, 0);
    string s = str1;
    env->ReleaseStringUTFChars(jstring1, str1);
    return s;
}

static string urlEncodeToStr(string str) {
    size_t len = str.length();
    size_t max_encoded_len = 3 * len + 1;
    std::vector<uint8_t> buf(max_encoded_len);
    url_encode(const_cast<char*>(str.c_str()), (char*)buf.data());
    return (char*)buf.data();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_testRoot(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    std::string result = kernel_root::get_root_test_report(strRootKey.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_runRootCmd(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring cmd) {
    string strRootKey = jstringToStr(env, rootKey);
    string strCmd = jstringToStr(env, cmd);

    string result;
    KRootErr err = kernel_root::run_root_cmd(strRootKey.c_str(), strCmd.c_str(), result);
    stringstream sstr;
    sstr << "run_root_cmd " << to_string(err).c_str() << ", result:" << result;
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_rootExecProcessCmd(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring cmd) {
    string strRootKey = jstringToStr(env, rootKey);
    string strCmd = jstringToStr(env, cmd);

    KRootErr err = kernel_root::root_exec_process(strRootKey.c_str(), strCmd.c_str());

    stringstream sstr;
    sstr << "root_exec_process " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_installSu(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    //安装su工具套件
    std::string su_hide_full_path;
    KRootErr err = kernel_root::install_su(strRootKey.c_str(), su_hide_full_path);

    stringstream sstr;
    sstr << "install su " << to_string(err).c_str() << ", su_hide_full_path:" << su_hide_full_path << std::endl;
    g_last_su_file_path = su_hide_full_path;
    if (is_ok(err)) sstr << "install_su done."<< std::endl;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getLastSuFilePath(
        JNIEnv* env,
        jclass /* this */) {
    return env->NewStringUTF(g_last_su_file_path.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_uninstallSu(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    stringstream sstr;

    KRootErr err = kernel_root::uninstall_su(strRootKey.c_str());
    sstr << "uninstall_su " << to_string(err).c_str() << std::endl;
    if (is_failed(err)) return env->NewStringUTF(sstr.str().c_str());
    g_last_su_file_path.clear();
    sstr << "uninstall_su done.";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_autoSuEnvInject(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {
    
    if(g_last_su_file_path.empty()) return env->NewStringUTF("【错误】请先安装部署su");
    string strRootKey = jstringToStr(env, rootKey);
    string strTargetProcessCmdline = jstringToStr(env, targetProcessCmdline);

    stringstream sstr;

    //杀光所有历史进程
    std::set<pid_t> out;
    KRootErr err = kernel_root::find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), out);
    sstr << "find_all_cmdline_process " << to_string(err).c_str() << ", cnt:"<<out.size() << std::endl;
    if (is_failed(err)) return env->NewStringUTF(sstr.str().c_str());
    std::string kill_cmd;
    for (pid_t t : out) {
        err =  kernel_root::kill_process(strRootKey.c_str(), t);
        sstr << "kill_ret " << to_string(err).c_str() << std::endl;
        if (is_failed(err)) return env->NewStringUTF(sstr.str().c_str());
    }
    pid_t pid;
    err = kernel_root::wait_and_find_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), 60*1000, pid);
    std::string su_dir_path = is_ok(err) ? (std::filesystem::path(g_last_su_file_path).parent_path().string() + "/") : "";
    sstr << "auto_su_env_inject("<< to_string(err).c_str() <<", " <<  su_dir_path <<")" << std::endl;
    if (is_failed(err)) return env->NewStringUTF(sstr.str().c_str());
    err = kernel_root::inject_process_env64_PATH_wrapper(strRootKey.c_str(), pid, su_dir_path.c_str());
    sstr << "auto_su_env_inject ret val:" << to_string(err).c_str() << std::endl;
    if (is_failed(err)) return env->NewStringUTF(sstr.str().c_str());
    sstr << "auto_su_env_inject done.";
    return env->NewStringUTF(sstr.str().c_str());
}



extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getAllCmdlineProcess(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    std::stringstream ss;
    std::map<pid_t, std::string> pid_map;
    KRootErr err = kernel_root::get_all_cmdline_process(strRootKey.c_str(), pid_map);
    if (is_failed(err)) {
        ss << "get_all_cmdline_process " << to_string(err).c_str() << std::endl;
        return env->NewStringUTF(ss.str().c_str());
    }
    cJSON *root = cJSON_CreateArray();
    for (auto &iter : pid_map) {
        cJSON *item = cJSON_CreateObject();
        string encodeName = urlEncodeToStr(iter.second);
        cJSON_AddNumberToObject(item, "pid",  iter.first);
        cJSON_AddStringToObject(item, "name", encodeName.c_str());
        cJSON_AddItemToArray(root, item);
    }
    ss << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(ss.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_parasitePrecheckApp(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {
    string strRootKey = jstringToStr(env, rootKey);
    string strTargetProcessCmdline = jstringToStr(env, targetProcessCmdline);

    stringstream sstr;
    std::set<pid_t> test_pid;
    KRootErr err = kernel_root::find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), test_pid);
    if (is_failed(err)) {
        sstr << "find_all_cmdline_process " << to_string(err).c_str() << ", cnt:"<< test_pid.size() << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    if (test_pid.size() == 0) {
        sstr << "目标进程不存在" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    std::map<std::string, kernel_root::AppDynlibStatus> dynlibPathList;
    err = kernel_root::parasite_precheck_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), dynlibPathList);
    if (is_failed(err)) {
        sstr << "parasite_precheck_app ret val:" << to_string(err).c_str() << std::endl;
        if(err == KRootErr::ERR_EXIST_32BIT) sstr << "此目标APP为32位应用，无法寄生" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    if (!dynlibPathList.size()) {
        sstr << "无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    cJSON *root = cJSON_CreateArray();
    for (auto &iter : dynlibPathList) {
        cJSON *item = cJSON_CreateObject();
        string encodeName = urlEncodeToStr(iter.first);
        cJSON_AddStringToObject(item, "name", encodeName.c_str());
        cJSON_AddNumberToObject(item, "status",  iter.second);
        cJSON_AddItemToArray(root, item);
    }
    sstr << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(sstr.str().c_str());

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_parasiteImplantApp(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring targetSoFullPath) {
    string strRootKey = jstringToStr(env, rootKey);
    string strTargetProcessCmdline = jstringToStr(env, targetProcessCmdline);
    string strTargetSoFullPath = jstringToStr(env, targetSoFullPath);

    stringstream sstr;
    KRootErr err = kernel_root::parasite_implant_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), strTargetSoFullPath.c_str());
    if (is_failed(err)) {
        sstr << "parasite_implant_app " << to_string(err).c_str() << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "parasite_implant_app done.";
    return env->NewStringUTF(sstr.str().c_str());

}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_parasiteImplantSuEnv(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring targetSoFullPath) {
    if(g_last_su_file_path.empty()) {
        return env->NewStringUTF("【错误】请先安装部署su");
    }
    string strRootKey = jstringToStr(env, rootKey);
    string strTargetProcessCmdline = jstringToStr(env, targetProcessCmdline);
    string strTargetSoFullPath = jstringToStr(env, targetSoFullPath);

    std::string su_dir_path = std::filesystem::path(g_last_su_file_path).parent_path().string() + "/";

    stringstream sstr;
    KRootErr err = kernel_root::parasite_implant_su_env(strRootKey.c_str(), strTargetProcessCmdline.c_str(), strTargetSoFullPath.c_str(), su_dir_path.c_str());
    if (is_failed(err)) {
        sstr << "parasite_implant_su_env " << to_string(err).c_str() << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "parasite_implant_su_env done.";
    return env->NewStringUTF(sstr.str().c_str());

}
