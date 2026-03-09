LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_fake_thermal

LOCAL_SRC_FILES := ../module_fake_thermal.cpp ../patch_base.cpp ../patch_thermal_zone_get_temp.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)


