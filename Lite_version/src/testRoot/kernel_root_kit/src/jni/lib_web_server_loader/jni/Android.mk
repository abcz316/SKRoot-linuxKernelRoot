LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_web_server_loader
LOCAL_SRC_FILES := \
../lib_web_server_loader.cpp \
../shm_open_anon.cpp

KERNEL_ROOT_KIT := $(LOCAL_PATH)/../../../../../kernel_root_kit
LOCAL_C_INCLUDES  += $(KERNEL_ROOT_KIT)/include
LOCAL_C_INCLUDES  += $(KERNEL_ROOT_KIT)/src/jni/
LOCAL_LDFLAGS  += $(KERNEL_ROOT_KIT)/lib/libkernel_root_kit_static.a

include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_SHARED_LIBRARY)