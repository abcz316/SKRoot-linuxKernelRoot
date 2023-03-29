#ifndef TEST_ROOT_H_
#define TEST_ROOT_H_
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <vector>
//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#undef TRACE
#define TRACE(fmt, ...)
#else
#ifdef __ANDROID__
#undef TRACE
#include <android/log.h>
#define LOG_TAG "JNIGlue"
//#define TRACE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#endif

#endif /* TEST_ROOT_H_ */
