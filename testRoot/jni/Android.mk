LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17 -fPIE -fvisibility=hidden -frtti -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE := testRoot
LOCAL_SRC_FILES := \
../testRoot.cpp \
../base64.cpp \
../kernel_root_kit/kernel_root_kit_process64_inject.cpp \
../kernel_root_kit/kernel_root_kit_ptrace_arm64_utils.cpp \
../kernel_root_kit/kernel_root_kit_su_install_helper.cpp

include $(BUILD_EXECUTABLE)
