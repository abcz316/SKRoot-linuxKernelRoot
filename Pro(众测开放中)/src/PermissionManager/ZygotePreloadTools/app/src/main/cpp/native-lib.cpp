#include <jni.h>
#include <string>
#include <sstream>
#include <thread>

#include "kernel_module_kit_umbrella.h"

#include "oplusDeviceDetect.h"

using namespace std;
using namespace skroot_env;

static std::string jstringToStr(JNIEnv* env, jstring value) {
    if (env == nullptr || value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_zygotepreloadtools_bridge_NativeBridge_testSkrootBasics(JNIEnv* env, jclass /* this */, jstring rootKey, jstring item) {
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

KModErr oneplus_bypass_stage1_and_2(const char* root_key, void (*cb)(const char* info));
extern "C" JNIEXPORT jstring JNICALL Java_com_android_zygotepreloadtools_bridge_NativeBridge_oneplusBypassWriteStage1(JNIEnv* env, jclass /* this */) {
    if(!device_detect::is_oplus_device()) return env->NewStringUTF("not oplus device");
    thread_local std::string tls_result;
    auto cb = [](const char* out_str) { tls_result = out_str; };
    oneplus_bypass_stage1_and_2("", cb);
    return env->NewStringUTF(tls_result.c_str());
}