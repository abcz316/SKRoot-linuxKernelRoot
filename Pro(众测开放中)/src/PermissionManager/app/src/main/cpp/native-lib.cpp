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

#include "urlEncodeUtils.h"
#include "sysNodeHelper.h"
#include "oneplusDeviceDetect.h"
#include "cJSON.h"

using namespace std;
using namespace skroot_env;

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

static cJSON * suAuthToJsonObj(su_auth_item & auth) {
    cJSON *item = cJSON_CreateObject();
    string encodeAppName = urlEncodeToStr(auth.app_package_name);
    cJSON_AddStringToObject(item, "app_package_name", encodeAppName.c_str());
    return item;
}

static cJSON * moduleDescToJsonObj(module_desc & desc) {
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

static std::string moduleRunStateToString(ModuleRunState state) {
    static const std::map<ModuleRunState, const char*> kStateNameMap = {
            {ModuleRunState::NotRunning,              "NotRunning"},
            {ModuleRunState::Running,              "Running"},
            {ModuleRunState::Abnormal,             "Abnormal"},
            {ModuleRunState::RemovedPendingReboot, "RemovedPendingReboot"},
    };
    auto it = kStateNameMap.find(state);
    if (it != kStateNameMap.end()) return it->second;
    return "";
}

static cJSON * moduleRecordToJsonObj(module_record & record) {
    cJSON *item = cJSON_CreateObject();
    cJSON_AddItemToObject(item, "desc", moduleDescToJsonObj(record.desc));
    cJSON_AddStringToObject(item, "state", moduleRunStateToString(record.state).c_str());
    return item;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_installSkrootEnv(
        JNIEnv* env, jclass /* this */, jstring rootKey, jboolean isHotload) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = install_skroot_environment(strRootKey.c_str(), isHotload ? InstallMode::HotLoad : InstallMode::Boot);
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

    KModErr err = uninstall_skroot_environment(strRootKey.c_str());
    stringstream sstr;
    sstr << "uninstall_skroot_environment: " << to_string(err).c_str();
	if(is_ok(err)) sstr  << "，将在重启后生效";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSkrootEnvState(
        JNIEnv* env, jclass /* this */, jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

	using SkrootEnvState = SkrootEnvState;
	static std::map<SkrootEnvState, const char*> m = {
        {SkrootEnvState::NotInstalled, "NotInstalled"},
        {SkrootEnvState::Running,      "Running"},
        {SkrootEnvState::Fault,        "Fault"},
    };
	SkrootEnvState state = get_skroot_environment_state(strRootKey.c_str());
    return env->NewStringUTF(m[state]);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_linux_permissionmanager_bridge_NativeBridge_getSystemStatusJson(JNIEnv* env, jclass /* this */) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "selinux", get_selinux_enforce_status());
    cJSON_AddNumberToObject(root, "seccomp", get_seccomp_status());
    cJSON_AddBoolToObject(root, "adb", is_enable_adb());
    std::string json = cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(json.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getInstalledSkrootEnvVersion(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    SkrootSdkVersion ver;
    KModErr err = get_installed_skroot_environment_version(strRootKey.c_str(), ver);
    if(is_failed(err)) return env->NewStringUTF(to_string(err).c_str());

    stringstream sstr;
    sstr << ver.major << "." << ver.minor << "." << ver.patch;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSdkVersion(
        JNIEnv* env,
        jclass /* this */) {
    SkrootSdkVersion ver = get_sdk_version();
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

    string result = get_root_status_report(strRootKey.c_str());
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
    KModErr err = run_root_cmd(strRootKey.c_str(), strCmd.c_str(), result);
    stringstream sstr;
    sstr << "run_root_cmd err: " << to_string(err).c_str() << ", result:" << result;
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

    KModErr err = add_su_auth_list(strRootKey.c_str(), strAppPackageName.c_str());
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

    KModErr err = remove_su_auth_list(strRootKey.c_str(), strModUuid.c_str());
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
    vector<su_auth_item> pkgs;
    KModErr err = get_su_auth_list(strRootKey.c_str(), pkgs);
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

    KModErr err = clear_su_auth_list(strRootKey.c_str());
    stringstream sstr;
    sstr << "clear_su_auth_list: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_installSkrootModule(
        JNIEnv* env, jclass /* this */, jstring rootKey, jstring zipFilePath, jboolean isDevRunOnceMode) {
    string strRootKey = jstringToStr(env, rootKey);
    string strZipFilePath = jstringToStr(env, zipFilePath);

    stringstream sstr;
    string reason;
    KModErr err = KModErr::ERR_MODULE_ASM;
    if(isDevRunOnceMode) {
        err = install_module_dev_run_once(strRootKey.c_str(), strZipFilePath.c_str(), reason);
        sstr << "install_module_dev_run_once: " << to_string(err).c_str();
    } else {
        err = install_module(strRootKey.c_str(), strZipFilePath.c_str(), reason);
        sstr << "install_module: " << to_string(err).c_str();
    }
    if(is_failed(err)) sstr << ", reason: " << reason.c_str();
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

    KModErr err = uninstall_module(strRootKey.c_str(), strModUuid.c_str());
    stringstream sstr;
    sstr << "uninstall_module: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_getSkrootModuleList(JNIEnv* env, jclass /* this */, jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    stringstream ss;
    vector<module_record> list;
    KModErr err = get_all_modules_list(strRootKey.c_str(), list);
    if(is_failed(err)) {
        ss << "get_all_modules_list: " << to_string(err).c_str();
        return env->NewStringUTF(ss.str().c_str());
    }

    cJSON *root = cJSON_CreateArray();
    for (auto & iter : list) {
        cJSON *item = moduleRecordToJsonObj(iter);
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
    module_desc desc;
    KModErr err = parse_module_desc_from_zip_file(strRootKey.c_str(), strZipFilePath.c_str(), desc);
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
    KModErr err = features::web_ui::start_module_web_ui_server_async(strRootKey.c_str(), strModUuid.c_str(), port);
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

    KModErr err = set_boot_fail_protect_enabled(strRootKey.c_str(), enable);

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
    return is_boot_fail_protect_enabled(strRootKey.c_str()) ? JNI_TRUE : JNI_FALSE;
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_setAdbForcedDisabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jboolean enable) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = set_adb_forced_disabled(strRootKey.c_str(), enable);

    stringstream sstr;
    sstr << "set_adb_forced_disabled: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_isAdbForcedDisabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    return is_adb_forced_disabled(strRootKey.c_str()) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_testSkrootBasics(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jstring item) {
    string strRootKey = jstringToStr(env, rootKey);
    string strItem = jstringToStr(env, item);

    BasicItem basicItem;
    if(strItem == "Channel") basicItem = BasicItem::Channel;
    else if(strItem == "KernelBase") basicItem = BasicItem::KernelBase;
    else if(strItem == "WriteTest") basicItem = BasicItem::WriteTest;
    else if(strItem == "ReadTrampoline") basicItem = BasicItem::ReadTrampoline;
    else if(strItem == "WriteTrampoline") basicItem = BasicItem::WriteTrampoline;
    else if(strItem == "PhysAddrCalc") basicItem = BasicItem::PhysAddrCalc;
    else return env->NewStringUTF(strItem.c_str());

    stringstream sstr;
    string info;
    KModErr err = test_skroot_basics(strRootKey.c_str(), basicItem, info);
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

    DeafultModuleName defName;
    if(strName == "RootBridgePrint") defName = DeafultModuleName::RootBridgePrint;
    else if(strName == "RootBridgeExec") defName = DeafultModuleName::RootBridgeExec;
    else if(strName == "SuRedirectPrint") defName = DeafultModuleName::SuRedirectPrint;
    else if(strName == "TombstonesPurgePrint") defName = DeafultModuleName::TombstonesPurgePrint;
    else return env->NewStringUTF(strName.c_str());

    stringstream sstr;
    string info;
    KModErr err = test_skroot_deafult_module(strRootKey.c_str(), defName, info);
    sstr << info.c_str() << "\n";
    sstr << "Test " << strName.c_str() <<": " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_restartZygote64(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    KModErr err = restart_zygote64(strRootKey.c_str());
    stringstream sstr;
    sstr << "restart_zygote64: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_setSkrootLogEnabled(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey,
        jboolean enable) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = set_skroot_log_enabled(strRootKey.c_str(), enable);

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
    return is_skroot_log_enabled(strRootKey.c_str()) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_readSkrootLog(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    string log;
    KModErr err = read_skroot_log(strRootKey.c_str(), log);
    if(is_failed(err)) log = to_string(err);
    return env->NewStringUTF(log.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_bridge_NativeBridge_clearSkrootLog(
        JNIEnv* env,
        jclass /* this */,
        jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);

    KModErr err = clear_skroot_log(strRootKey.c_str());
    stringstream sstr;
    sstr << "clear_skroot_log: " << to_string(err).c_str();
    return env->NewStringUTF(sstr.str().c_str());
}

KModErr oneplus_bypass_stage1_and_2(const char* root_key, void (*cb)(const char* info));
extern "C" JNIEXPORT jstring JNICALL Java_com_linux_permissionmanager_bridge_NativeBridge_oneplusBypassWriteStage1(
        JNIEnv* env, jclass /* this */, jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    if(!device_detect::is_oneplus_device()) return env->NewStringUTF("not oneplus device");
    thread_local std::string tls_result;
    auto cb = [](const char* out_str) { tls_result = out_str; };
    oneplus_bypass_stage1_and_2(strRootKey.c_str(), cb);
    return env->NewStringUTF(tls_result.c_str());
}

bool oneplus_bypass_is_work_normal(const char* root_key);
extern "C" JNIEXPORT jboolean JNICALL Java_com_linux_permissionmanager_bridge_NativeBridge_oneplusBypassIsWorkNormal(
        JNIEnv* env, jclass /* this */, jstring rootKey) {
    string strRootKey = jstringToStr(env, rootKey);
    if(!device_detect::is_oneplus_device()) return false;
    return oneplus_bypass_is_work_normal(strRootKey.c_str());
}
