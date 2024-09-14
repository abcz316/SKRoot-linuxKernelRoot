LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_su_env
LOCAL_CPPFLAGS += -std=c++17 -fPIC -fvisibility=hidden -frtti -fexceptions
LOCAL_SRC_FILES := \
lib_su_env/lib_su_env.cpp
LOCAL_SHARED_LIBRARIES := lib_su_env
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := lib_root_server
LOCAL_CPPFLAGS += -std=c++17 -fPIC -fvisibility=hidden -frtti -fexceptions
LOCAL_SRC_FILES := \
lib_root_server/lib_root_server.cpp \
kernel_root_kit/kernel_root_kit_process64_inject.cpp \
kernel_root_kit/kernel_root_kit_ptrace_arm64_utils.cpp \
kernel_root_kit/kernel_root_kit_su_install_helper.cpp \
kernel_root_kit/kernel_root_kit_parasite_app.cpp \
kernel_root_kit/kernel_root_kit_parasite_patch_elf.cpp \
utils/cJSON.cpp

LOCAL_SHARED_LIBRARIES := lib_root_server
include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17 -fPIE -fvisibility=hidden -frtti -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE := su
LOCAL_SRC_FILES := \
su/su.cpp

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17 -fPIE -fvisibility=hidden -frtti -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE := testRoot
LOCAL_SRC_FILES := \
testRoot.cpp \
kernel_root_kit/kernel_root_kit_process64_inject.cpp \
kernel_root_kit/kernel_root_kit_ptrace_arm64_utils.cpp \
kernel_root_kit/kernel_root_kit_su_install_helper.cpp \
kernel_root_kit/kernel_root_kit_parasite_app.cpp \
kernel_root_kit/kernel_root_kit_parasite_patch_elf.cpp

include $(BUILD_EXECUTABLE)
