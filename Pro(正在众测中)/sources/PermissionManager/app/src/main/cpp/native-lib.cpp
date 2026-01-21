#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <filesystem>
#include <sys/capability.h>


#include "kernel_module_kit_umbrella.h"

#include "command.h"
#include "exec_process.h"
#include "test.h"
#include "urlEncodeUtils.h"
#include "cJSON.h"

using namespace std;

static string jstringToStr(JNIEnv* env, jstring jstring1) {
    const char *str1 = env->GetStringUTFChars(jstring1, 0);
    string s = str1;
    env->ReleaseStringUTFChars(jstring1, str1);
    return s;
}

static string urlEncodeToStr(string str) {
    size_t len = str.length();
    size_t max_encoded_len = 3 * len + 1;
    vector<uint8_t> buf(max_encoded_len);
    url_encode(const_cast<char*>(str.c_str()), (char*)buf.data());
    return (char*)buf.data();
}

static cJSON * suAuthToJsonObj(skroot_env::su_auth_item & auth) {
    cJSON *item = cJSON_CreateObject();
    string encodeAppName = urlEncodeToStr(auth.app_package_name);
    cJSON_AddStringToObject(item, "app_package_name", encodeAppName.c_str());
    return item;
}

static cJSON * moduleDescToJsonObj(skroot_env::module_desc & desc) {
    cJSON *item = cJSON_CreateObject();
    string encodeName = urlEncodeToStr(desc.name);
    string encodeVer = urlEncodeToStr(desc.version);
    string encodeDesc = urlEncodeToStr(desc.desc);
    string encodeAuthor = urlEncodeToStr(desc.author);
    string encodeUuid = urlEncodeToStr(desc.uuid);
    string encodeUpdateJson = urlEncodeToStr(desc.update_json);
    stringstream ss;
    ss << desc.min_sdk_ver.major << "." << desc.min_sdk_ver.minor << "." << desc.min_sdk_ver.patch;
    string encodeMiniSDK = urlEncodeToStr(ss.str().c_str());
    cJSON_AddStringToObject(item, "name", encodeName.c_str());
    cJSON_AddStringToObject(item, "ver", encodeVer.c_str());
    cJSON_AddStringToObject(item, "desc", encodeDesc.c_str());
    cJSON_AddStringToObject(item, "author", encodeAuthor.c_str());
    cJSON_AddStringToObject(item, "uuid", encodeUuid.c_str());
    cJSON_AddStringToObject(item, "update_json", encodeUpdateJson.c_str());
    cJSON_AddBoolToObject(item, "web_ui", desc.web_ui);
    cJSON_AddStringToObject(item, "min_sdk_ver", encodeMiniSDK.c_str());
    return item;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_installSkrootEnv(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = skroot_env::install_skroot_environment(strRootKey.c_str());
    stringstream sstr;
    sstr << "install_skroot_environment: " << to_string(err).c_str();
	if(is_ok(err)) sstr  << "，将在重启后生效";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_uninstallSkrootEnv(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = skroot_env::uninstall_skroot_environment(strRootKey.c_str());
    stringstream sstr;
    sstr << "uninstall_skroot_environment: " << to_string(err).c_str();
	if(is_ok(err)) sstr  << "，将在重启后生效";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSkrootEnvState(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

	using SkrootEnvState = skroot_env::SkrootEnvState;
	static std::map<SkrootEnvState, const char*> m = {
        {SkrootEnvState::NotInstalled, "NotInstalled"},
        {SkrootEnvState::Running,      "Running"},
        {SkrootEnvState::Fault,        "Fault"},
    };
	SkrootEnvState state = skroot_env::get_skroot_environment_state(strRootKey.c_str());
    return env->NewStringUTF(m[state]);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getInstalledSkrootEnvVersion(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    skroot_env::SkrootSdkVersion ver;
    KModErr err = skroot_env::get_installed_skroot_environment_version(strRootKey.c_str(), ver);
    if(is_failed(err)) return env->NewStringUTF(to_string(err).c_str());

    stringstream sstr;
    sstr << ver.major << "." << ver.minor << "." << ver.patch;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSdkVersion(
        JNIEnv* env,
        jclass /* this */) {
    skroot_env::SkrootSdkVersion ver = skroot_env::get_sdk_version();
    stringstream sstr;
    sstr << ver.major << "." << ver.minor << "." << ver.patch;
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_testRoot(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    string result = get_root_test_report(strRootKey.c_str());
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
    bool success = run_root_cmd(strRootKey.c_str(), strCmd.c_str(), result);
    stringstream sstr;
    sstr << "run_root_cmd err: " << (success ? "OK" : "FAILED") << ", result:" << result;
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

    bool success = root_exec_process(strRootKey.c_str(), strCmd.c_str());
    stringstream sstr;
    sstr << "root_exec_process err: " << (success ? "OK" : "FAILED");
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_addSuAuth(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring appPackageName) {
    string strRootKey = jstringToStr(env, rootKey);
    string strAppPackageName = jstringToStr(env, appPackageName);

    KModErr err = skroot_env::add_su_auth_list(strRootKey.c_str(), strAppPackageName.c_str());
    stringstream sstr;
    sstr << "add_su_auth_list: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_removeSuAuth(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring modUuid) {
    string strRootKey = jstringToStr(env, rootKey);
    string strModUuid = jstringToStr(env, modUuid);

    KModErr err = skroot_env::remove_su_auth_list(strRootKey.c_str(), strModUuid.c_str());
    stringstream sstr;
    sstr << "remove_su_auth_list: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSuAuthList(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    stringstream ss;
    vector<skroot_env::su_auth_item> pkgs;
    KModErr err = skroot_env::get_su_auth_list(strRootKey.c_str(), pkgs);
    if(is_failed(err)) {
        ss << "get_su_auth_list: " << to_string(err).c_str();
        return env->NewStringUTF(ss.str().c_str());
    }

    cJSON *root = cJSON_CreateArray();
    for (auto & iter : pkgs) {
        cJSON *item = suAuthToJsonObj(iter);
        cJSON_AddItemToArray(root, item);
    }
    ss << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(ss.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_clearSuAuthList(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = skroot_env::clear_su_auth_list(strRootKey.c_str());
    stringstream sstr;
    sstr << "clear_su_auth_list: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_installSkrootModule(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring zipFilePath) {
    string strRootKey = jstringToStr(env, rootKey);
    string strZipFilePath = jstringToStr(env, zipFilePath);

    string reason;
    KModErr err = skroot_env::install_module(strRootKey.c_str(), strZipFilePath.c_str(), reason);
    stringstream sstr;
    if(is_ok(err)) sstr << "install_module: " << to_string(err).c_str();
    else sstr << "install_module: " << to_string(err).c_str() << ", reason: " << reason.c_str();
    return env->NewStringUTF(sstr.str().c_str());
}



extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_uninstallSkrootModule(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring modUuid) {
    string strRootKey = jstringToStr(env, rootKey);
    string strModUuid = jstringToStr(env, modUuid);

    KModErr err = skroot_env::uninstall_module(strRootKey.c_str(), strModUuid.c_str());
    stringstream sstr;
    sstr << "uninstall_module: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSkrootModuleList(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jboolean runningOnly) {
    string strRootKey = jstringToStr(env, rootKey);

    stringstream ss;
    vector<skroot_env::module_desc> list;
    KModErr err = skroot_env::get_all_modules_list(strRootKey.c_str(), list, runningOnly ? skroot_env::ModuleListMode::RunningOnly : skroot_env::ModuleListMode::All);
    if(is_failed(err)) {
        ss << "get_all_modules_list: " << to_string(err).c_str();
        return env->NewStringUTF(ss.str().c_str());
    }

    cJSON *root = cJSON_CreateArray();
    for (auto & iter : list) {
        cJSON *item = moduleDescToJsonObj(iter);
        cJSON_AddItemToArray(root, item);
    }
    ss << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(ss.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_parseSkrootModuleDesc(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring zipFilePath) {
    string strRootKey = jstringToStr(env, rootKey);
    string strZipFilePath = jstringToStr(env, zipFilePath);

    stringstream ss;
    skroot_env::module_desc desc;
    KModErr err = skroot_env::parse_module_desc_from_zip_file(strRootKey.c_str(), strZipFilePath.c_str(), desc);
    if(is_ok(err)) {
        cJSON *root = moduleDescToJsonObj(desc);
        ss << cJSON_Print(root);
        cJSON_Delete(root);
    } else {
        ss << "parse_module_desc_from_zip_file: " << to_string(err).c_str();
    }
    return env->NewStringUTF(ss.str().c_str());

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_openSkrootModuleWebUI(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring modUuid) {
    string strRootKey = jstringToStr(env, rootKey);
    string strModUuid = jstringToStr(env, modUuid);

    int port = 0;
    KModErr err = skroot_env::features::web_ui::start_module_web_ui_server_async(strRootKey.c_str(), strModUuid.c_str(), port);
    stringstream sstr;
    sstr << "start_module_web_ui_server_async: " << to_string(err).c_str() << ", port:" << port;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_setBootFailProtectEnabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jboolean enable) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = skroot_env::set_boot_fail_protect_enabled(strRootKey.c_str(), enable);

    stringstream sstr;
    sstr << "set_boot_fail_protect_enabled: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_isBootFailProtectEnabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    return skroot_env::is_boot_fail_protect_enabled(strRootKey.c_str()) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_testSkrootBasics(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring item) {
    string strRootKey = jstringToStr(env, rootKey);
    string strItem = jstringToStr(env, item);

    skroot_env::BasicItem basicItem;
    if(strItem == "Channel") basicItem = skroot_env::BasicItem::Channel;
    else if(strItem == "KernelBase") basicItem = skroot_env::BasicItem::KernelBase;
    else if(strItem == "WriteTest") basicItem = skroot_env::BasicItem::WriteTest;
    else if(strItem == "ReadTrampoline") basicItem = skroot_env::BasicItem::ReadTrampoline;
    else if(strItem == "WriteTrampoline") basicItem = skroot_env::BasicItem::WriteTrampoline;
    else return env->NewStringUTF(strItem.c_str());

    stringstream sstr;
    string info;
    KModErr err = skroot_env::test_skroot_basics(strRootKey.c_str(), basicItem, info);
    sstr << info.c_str() << "\n";
    sstr << "Test " << strItem.c_str() <<": " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_testSkrootDefaultModule(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring name) {
    string strRootKey = jstringToStr(env, rootKey);
    string strName = jstringToStr(env, name);

    skroot_env::DeafultModuleName defName;
    if(strName == "RootBridge") defName = skroot_env::DeafultModuleName::RootBridge;
    else if(strName == "SuRedirect") defName = skroot_env::DeafultModuleName::SuRedirect;
    else return env->NewStringUTF(strName.c_str());

    stringstream sstr;
    string info;
    KModErr err = skroot_env::test_skroot_deafult_module(strRootKey.c_str(), defName, info);
    sstr << info.c_str() << "\n";
    sstr << "Test " << strName.c_str() <<": " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_setSkrootLogEnabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jboolean enable) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = skroot_env::set_skroot_log_enabled(strRootKey.c_str(), enable);

    stringstream sstr;
    sstr << "set_skroot_log_enabled: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_isSkrootLogEnabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    return skroot_env::is_skroot_log_enabled(strRootKey.c_str()) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_readSkrootLog(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    string log;
    KModErr err = skroot_env::read_skroot_log(strRootKey.c_str(), log);
    if(is_failed(err)) log = to_string(err);
    return env->NewStringUTF(log.c_str());
}
