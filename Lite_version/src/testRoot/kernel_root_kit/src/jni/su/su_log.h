#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define SU_PRINTF(fmt, ...)
#else
#define SU_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

