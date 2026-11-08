#pragma once
#include <iostream>

namespace kernel_root {
enum AppDynlibStatus: int {
    Unknown = 0,
    Running,
    NotRunning,
};
}
