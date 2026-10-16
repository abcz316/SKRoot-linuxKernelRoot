#include <jni.h>
#include <unistd.h>
#include <linux/capability.h>
#include <sys/wait.h>
#include <lsplt.hpp>
#include "logging.h"
#include "android_filesystem_config.h"
#define arraysize(array) (sizeof(array)/sizeof(array[0]))

static int skip_capset(cap_user_header_t header __unused, cap_user_data_t data __unused) {
    LOGD("Skip capset");
    return 0;
}

static void signal_handler(int sig) {
    if (sig != SIGSYS) return;
    LOGW("received signal: SIGSYS, setresuid fail");
}

static bool str_ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

jint JNI_OnLoad(JavaVM *, void *v __unused) {
    signal(SIGSYS, signal_handler);

    auto maps = lsplt::MapInfo::Scan();
    bool hook_registered = false;
    for (const auto &map: maps) {
        if (str_ends_with(map.path, "/libandroid_runtime.so")) {
            LOGV("Found: dev=%lu, inode=%lu, path=%s",
                 (unsigned long) map.dev, (unsigned long) map.inode, map.path.c_str());
            if (lsplt::RegisterHook(map.dev, map.inode, "capset", (void *) skip_capset, nullptr)) {
                hook_registered = true;
                LOGD("Hook registered for capset");
                break;
            } else {
                LOGE("Failed to register hook for capset");
            }
        }
    }

    if (hook_registered) {
        if (!lsplt::CommitHook()) {
            PLOGE("lsplt CommitHook failed");
        }
    } else {
        LOGE("libandroid_runtime.so not found or hook registration failed");
    }

    return JNI_VERSION_1_6;
}
