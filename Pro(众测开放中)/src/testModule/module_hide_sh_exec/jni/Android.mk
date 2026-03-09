LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_hide_sh_exec

LOCAL_SRC_FILES := ../module_hide_sh_exec.cpp ../su_interactive.cpp ../idle_killer.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)


