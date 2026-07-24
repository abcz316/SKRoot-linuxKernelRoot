LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := teesimulator_skpro
LOCAL_SRC_FILES := module.cpp
LOCAL_C_INCLUDES := $(KERNEL_KIT_PATH)/include
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)

include $(KERNEL_KIT_PATH)/Android.mk
