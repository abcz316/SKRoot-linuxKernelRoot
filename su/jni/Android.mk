LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17 -fPIE -fvisibility=hidden -frtti -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE    := su
LOCAL_SRC_FILES :=  \
../su.cpp \
../base64.cpp \

include $(BUILD_EXECUTABLE)
