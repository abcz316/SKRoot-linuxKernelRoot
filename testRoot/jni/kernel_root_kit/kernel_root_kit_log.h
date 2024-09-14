#ifndef _KERNEL_ROOT_KIT_LOG_H_
#define _KERNEL_ROOT_KIT_LOG_H_
#include <iostream>
namespace kernel_root {
#define QUIET_KERNEL_ROOT_KIT_PRINTF

#ifdef QUIET_KERNEL_ROOT_KIT_PRINTF
#undef ROOT_PRINTF
#define ROOT_PRINTF(fmt, ...)
#else
#ifdef __ANDROID__
#undef ROOT_PRINTF
#include <android/log.h>
//#define ROOT_PRINTF(...) __android_log_print(ANDROID_LOG_ERROR, "JNIkernel_root", __VA_ARGS__)
#define ROOT_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define ROOT_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#endif
}
#endif /* _KERNEL_ROOT_KIT_LOG_H_ */
