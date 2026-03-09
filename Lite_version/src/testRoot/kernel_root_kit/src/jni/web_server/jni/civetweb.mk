LOCAL_PATH := $(call my-dir)

CIVETWEB_ROOT := $(LOCAL_PATH)/../civetweb-1.16

CIVETWEB_SRCS := \
    $(patsubst $(LOCAL_PATH)/%,%,$(wildcard $(CIVETWEB_ROOT)/src/*.c)) \
    $(patsubst $(LOCAL_PATH)/%,%,$(wildcard $(CIVETWEB_ROOT)/src/*.cpp))

CIVETWEB_INCLUDES := \
    $(CIVETWEB_ROOT)/include

LOCAL_SRC_FILES   += $(CIVETWEB_SRCS)
LOCAL_C_INCLUDES  += $(CIVETWEB_INCLUDES)
