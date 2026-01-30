LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := testInstall
LOCAL_SRC_FILES := ../command.cpp ../main.cpp ../exec_process.cpp ../test.cpp 

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../testModule/kernel_module_kit

LOCAL_C_INCLUDES += $(KERNEL_MODULE_KIT)/include

LOCAL_LDFLAGS += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a
LOCAL_LDLIBS += -lz
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)
