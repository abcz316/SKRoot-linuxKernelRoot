# DFRoot exploit native binaries (adapted into PermissionManager).
# Builds libdfroot.so (the .ko loader) as an ELF executable with .so naming
# so AGP packages it into jniLibs.

enable_language(ASM)

set(JNI_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -I${JNI_DIR}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${JNI_DIR} -Wall -Wextra -fno-stack-protector -fomit-frame-pointer")

# splicehelper is a freestanding static binary spliced into crash_dump64.
set(SPLICEHELPER "${JNI_DIR}/splicehelper")
add_custom_command(
    OUTPUT "${SPLICEHELPER}"
    COMMAND "${CMAKE_C_COMPILER}"
            --target=${CMAKE_C_COMPILER_TARGET}
            --sysroot=${CMAKE_SYSROOT}
            "${JNI_DIR}/splicehelper.c"
            -o "${SPLICEHELPER}"
            -nodefaultlibs -nostartfiles -ffreestanding -static
    COMMAND "${CMAKE_STRIP}" "${SPLICEHELPER}"
    DEPENDS "${JNI_DIR}/splicehelper.c"
    COMMENT "Building splicehelper"
)
add_custom_target(splicehelper_bin DEPENDS "${SPLICEHELPER}")

# AGP only packages lib*.so, so the executable is named libdfroot.so and lands
# in the APK's native lib dir.
add_executable(dfroot exp.c libcxx.S elf_parser.c)
add_dependencies(dfroot splicehelper_bin)
set_target_properties(dfroot PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

set_source_files_properties(exp.c PROPERTIES
    OBJECT_DEPENDS "${SPLICEHELPER}")

target_link_libraries(dfroot log)
target_link_options(dfroot PRIVATE -Wl,-z,max-page-size=16384)
