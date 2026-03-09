LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_su_env
LOCAL_SRC_FILES := ../lib_su_env.cpp
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_SHARED_LIBRARY)