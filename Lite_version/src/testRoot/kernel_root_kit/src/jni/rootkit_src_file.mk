KERNEL_ROOT_KIT_SRCS := \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_command.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_exec_process.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_fork_helper.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_test.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_parasite_app.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_parasite_patch_elf.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_process_cmdline_utils.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_process64_inject.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_ptrace_arm64_utils.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_unsafe_hide_dir.cpp \
    $(KERNEL_ROOT_KIT)/src/jni/rootkit_su_install.cpp
LOCAL_SRC_FILES += $(KERNEL_ROOT_KIT_SRCS)
LOCAL_C_INCLUDES += $(KERNEL_ROOT_KIT)
LOCAL_C_INCLUDES += $(KERNEL_ROOT_KIT)/include
LOCAL_C_INCLUDES += $(KERNEL_ROOT_KIT)/../su
