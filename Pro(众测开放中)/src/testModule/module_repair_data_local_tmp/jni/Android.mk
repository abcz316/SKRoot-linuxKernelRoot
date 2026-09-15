LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_repair_data_local_tmp

LOCAL_SRC_FILES := ../module_repair_data_local_tmp.cpp \
	../patch_base.cpp \
	../patch_filldir64.cpp \
	../patch_compat_filldir.cpp \
	../patch_inode_operations_getattr.cpp \
	../patch_mtk_hbt_filldir64.cpp \
	../patch_iterate_dir.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)


