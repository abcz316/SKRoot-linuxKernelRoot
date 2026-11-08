LOCAL_PATH := $(call my-dir)

KERNEL_MODULE_KIT ?= $(LOCAL_PATH)/../../dependencies/SKRoot-linuxKernelRoot/Pro(众测开放中)/src/testModule/kernel_module_kit
LKM_ROOT ?= $(LOCAL_PATH)/..

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_module_kit_static_prebuilt
LOCAL_SRC_FILES := $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libarchive_static_prebuilt
LOCAL_SRC_FILES := vendor/file_manager/prebuilt/arm64-v8a/libarchive.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := liblzma_static_prebuilt
LOCAL_SRC_FILES := vendor/file_manager/prebuilt/arm64-v8a/liblzma.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := susfs4skp_standalone
LOCAL_CPP_FEATURES += exceptions
LOCAL_CPPFLAGS += -std=c++20 -fexceptions -fno-rtti
LOCAL_SRC_FILES := sdk_entry.cpp \
    ../management/embedded.cpp ../management/service.cpp \
    ../management/backend.cpp ../management/config.cpp ../management/config_transfer.cpp \
    ../management/inventory.cpp ../management/common.cpp \
    vendor/file_manager/cJSON.cpp \
    vendor/file_manager/app_metadata_service.cpp \
    vendor/file_manager/file_manager_service.cpp \
    vendor/file_manager/file_manager_api.cpp \
    vendor/file_manager/archive_service.cpp \
    vendor/file_manager/archive_browser_service.cpp \
    vendor/file_manager/image_preview_service.cpp \
    vendor/file_manager/file_broker.cpp
LOCAL_C_INCLUDES += $(LOCAL_PATH) $(LKM_ROOT)/management \
    $(LKM_ROOT)/kernel $(KERNEL_MODULE_KIT)/include \
    $(LOCAL_PATH)/vendor/file_manager \
    $(LOCAL_PATH)/vendor/file_manager/third_party/libarchive/include
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static_prebuilt libarchive_static_prebuilt liblzma_static_prebuilt
LOCAL_LDLIBS += -llog -ldl -lz
include $(BUILD_SHARED_LIBRARY)
