#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <vector>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "kernel_module_kit_umbrella.h"

#define TEST(NUM, NAME)                                                    \
    do {                                                                   \
        int _test_idx = (NUM);                                             \
        printf("\n----- Test%d: %s -----\n", _test_idx, #NAME);            \
        KModErr err = (NAME)();                                            \
        printf("[%s] run done, return error code: %s\n", #NAME, to_string(err).c_str());     \
        printf("----- End of Test%d -----\n\n", _test_idx);                \
    } while (0)

#define REQUIRE_ROOT_OR_RETURN()                                      \
    do {                                                              \
        if (getuid() != 0) {                                          \
            printf("[ERROR] please run with ROOT permission.\n");      \
            return KModErr::ERR_MODULE_PARAM;                         \
        }                                                             \
    } while (0)

static std::string get_comm_prctl() {
    char name[16] = {0};
    if (prctl(PR_GET_NAME, name) == 0) return std::string(name);
    return "";
}
