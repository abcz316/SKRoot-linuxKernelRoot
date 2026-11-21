LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_hide_sh_exec

LOCAL_SRC_FILES := ../module_hide_sh_exec.cpp \
	../su_interactive/su_interactive.cpp \
	../su_interactive/pipe_su_interactive.cpp \
	../su_interactive/pty_su_interactive.cpp \
	../quick_actions/quick_actions.cpp \
	../idle_killer.cpp \
	../cJSON.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
# 模块根目录（json_helper.h / url_encode_utils.h / cJSON.h 等公共头）
LOCAL_C_INCLUDES  += $(LOCAL_PATH)/..
LOCAL_C_INCLUDES  += $(LOCAL_PATH)/../su_interactive
LOCAL_C_INCLUDES  += $(LOCAL_PATH)/../quick_actions
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)
