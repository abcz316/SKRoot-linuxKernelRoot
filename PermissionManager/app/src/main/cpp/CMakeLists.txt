# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.

project("permissionmanager")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
        permissionmanager

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        ../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_process64_inject.cpp
        ../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_ptrace_arm64_utils.cpp
        ../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_su_install_helper.cpp
        ../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_parasite_app.cpp
        ../../../../../testRoot/jni/kernel_root_kit/kernel_root_kit_parasite_patch_elf.cpp
        cJSON.c
        root.cpp)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        permissionmanager

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})