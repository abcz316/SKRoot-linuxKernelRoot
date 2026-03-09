LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_root_kit_static

LOCAL_PIC := true

KERNEL_ROOT_KIT := $(LOCAL_PATH)/../../../kernel_root_kit

LIBWEB_SERVER_LOADER_DATA  := $(KERNEL_ROOT_KIT)/src/jni/lib_web_server_loader/lib_web_server_loader_data.generated.h
ifneq ($(wildcard $(LIBWEB_SERVER_LOADER_DATA)),)
  LOCAL_CPPFLAGS += -include $(LIBWEB_SERVER_LOADER_DATA)
endif

SU_DATA_FILE  := $(KERNEL_ROOT_KIT)/src/jni/su/su_data.generated.h
ifneq ($(wildcard $(SU_DATA_FILE)),)
  LOCAL_CPPFLAGS += -include $(SU_DATA_FILE)
endif

include $(KERNEL_ROOT_KIT)/src/jni/rootkit_src_file.mk
include $(LOCAL_PATH)/build_macros_static.mk

include $(BUILD_STATIC_LIBRARY)