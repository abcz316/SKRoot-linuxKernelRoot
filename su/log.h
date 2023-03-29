#ifndef _LOG_H_
#define _LOG_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

#endif /* _LOG_H_ */
