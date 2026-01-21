LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_module_kit_test

LOCAL_SRC_FILES := \
     $(LOCAL_PATH)/../kernel_module_kit_test.cpp\

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

LOCAL_CPPFLAGS += -DKERNEL_MODULE_KIT_TEST
LOCAL_CFLAGS   += -DKERNEL_MODULE_KIT_TEST
include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_EXECUTABLE)


