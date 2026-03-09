COMMON_CPPFLAGS := \
    -std=c++20 \
    -fPIC \
    -fexceptions \
    -fvisibility=hidden \
    -fvisibility-inlines-hidden \
    -ffunction-sections \
    -fdata-sections \
    -flto=thin \
    -Oz -g0 \
    -fno-stack-protector

COMMON_INCLUDES := \
    $(LOCAL_PATH)/../../include

LOCAL_CPPFLAGS    += $(COMMON_CPPFLAGS)
LOCAL_C_INCLUDES  += $(COMMON_INCLUDES)
