COMMON_CPPFLAGS := \
    -std=c++20 \
    -fPIC \
    -fvisibility=hidden \
    -fno-stack-protector \
    -ffunction-sections \
    -fdata-sections \
    -flto=thin

COMMON_LDFLAGS := \
    -Wl,-O2 \
    -Wl,--gc-sections \
    -Wl,-s \
    -flto=thin
	
COMMON_INCLUDES := \
    $(LOCAL_PATH)/../../../

LOCAL_CPPFLAGS     += $(COMMON_CPPFLAGS)
LOCAL_LDFLAGS    += $(COMMON_LDFLAGS)
LOCAL_C_INCLUDES  += $(COMMON_INCLUDES)
