LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_fake_device

LOCAL_SRC_FILES := ../main.cpp ../utils/third_party/cJSON.cpp ../patch_base.cpp ../patch_selinux_inode_permission.cpp ../persist_dir_perm_manager.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)


