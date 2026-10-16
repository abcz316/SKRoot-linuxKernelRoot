#pragma once

#include <android/log.h>

#ifdef NDEBUG
#define LOGV(...)
#define LOGD(...)
#else
#define LOGV(...) (__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define LOGD(...) (__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#endif

#define LOGI(...) (__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGW(...) (__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define LOGE(...) (__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s\n", ##args, errno, strerror(errno))

#define TAG "Magica"
