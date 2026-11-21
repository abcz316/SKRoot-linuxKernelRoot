LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_process_mem_phys_rw

LOCAL_SRC_FILES := \
     $(LOCAL_PATH)/../main.cpp\
     $(LOCAL_PATH)/../process_mem_phys_rw/process_mem_phys.cpp\
     $(LOCAL_PATH)/../process_mem_phys_rw/kernel_patch/kernel_patch_manager.cpp\
     $(LOCAL_PATH)/../process_mem_phys_rw/kernel_patch/patch_base.cpp\
     $(LOCAL_PATH)/../process_mem_phys_rw/kernel_patch/patch_pagemap_read.cpp\
     $(LOCAL_PATH)/../process_mem_phys_rw/kernel_patch/patch_sys_prctl.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)


