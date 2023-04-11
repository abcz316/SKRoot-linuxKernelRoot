# 要求最低的 CMake 版本
cmake_minimum_required(VERSION 3.0)

# 启用 CMP0048 策略
cmake_policy(SET CMP0048 NEW)

# 设置项目名称和版本号
project(patch_kernel_root VERSION 1.0)


# 要求 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加头文件目录
include_directories(include)

# 添加所有源文件（排除测试文件）
file(GLOB SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/patch_kernel_root/*.cpp")
list(FILTER SRC_FILES EXCLUDE REGEX "^Byte2HexTest.cpp$")

# 添加可执行文件
add_executable(patch_kernel_root ${SRC_FILES})

# 添加测试文件
option(BUILD_TESTING "Build the tests" ON)
if(BUILD_TESTING)
    enable_testing()
    file(GLOB TEST_SOURCES "tests/*.cpp")
    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        target_link_libraries(${TEST_NAME} patch_kernel_root)
    endforeach()
endif()
