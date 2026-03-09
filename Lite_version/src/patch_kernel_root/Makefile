CXX := g++
CC  := gcc

TARGET := patch_kernel_root

INCLUDES := \
  -I. \
  -I3rdparty/capstone-5.0.7/include \
  -I3rdparty/asmjit2-src/src

DEFINES := \
  -DNDEBUG \
  -D_CONSOLE \
  -DCAPSTONE_HAS_ARM64 \
  -DCAPSTONE_USE_SYS_DYN_MEM

CXXFLAGS := -std=c++20 -O2 -Wall -Wextra $(DEFINES) $(INCLUDES)
CFLAGS   := -O2 -Wall -Wextra $(DEFINES) $(INCLUDES)

LIBS := -ldl -pthread

ASMJIT_SRCS := \
  3rdparty/asmjit2-src/src/asmjit/arm/a64assembler.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64builder.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64compiler.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64emithelper.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64formatter.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64func.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64instapi.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64instdb.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64operand.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/a64rapass.cpp \
  3rdparty/asmjit2-src/src/asmjit/arm/armformatter.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/archtraits.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/assembler.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/builder.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/codeholder.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/codewriter.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/compiler.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/constpool.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/cpuinfo.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/emithelper.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/emitter.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/emitterutils.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/environment.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/errorhandler.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/formatter.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/func.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/funcargscontext.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/globals.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/inst.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/instdb.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/jitallocator.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/jitruntime.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/logger.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/operand.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/osutils.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/ralocal.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/rapass.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/rastack.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/string.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/support.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/target.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/type.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/virtmem.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zone.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zonehash.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zonelist.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zonestack.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zonetree.cpp \
  3rdparty/asmjit2-src/src/asmjit/core/zonevector.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86assembler.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86builder.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86compiler.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86emithelper.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86formatter.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86func.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86instapi.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86instdb.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86operand.cpp \
  3rdparty/asmjit2-src/src/asmjit/x86/x86rapass.cpp

CAPSTONE_SRCS := \
  3rdparty/capstone-5.0.7/src/arch/AArch64/AArch64BaseInfo.c \
  3rdparty/capstone-5.0.7/src/arch/AArch64/AArch64Disassembler.c \
  3rdparty/capstone-5.0.7/src/arch/AArch64/AArch64InstPrinter.c \
  3rdparty/capstone-5.0.7/src/arch/AArch64/AArch64Mapping.c \
  3rdparty/capstone-5.0.7/src/arch/AArch64/AArch64Module.c \
  3rdparty/capstone-5.0.7/src/cs.c \
  3rdparty/capstone-5.0.7/src/Mapping.c \
  3rdparty/capstone-5.0.7/src/MCInst.c \
  3rdparty/capstone-5.0.7/src/MCInstrDesc.c \
  3rdparty/capstone-5.0.7/src/MCRegisterInfo.c \
  3rdparty/capstone-5.0.7/src/SStream.c \
  3rdparty/capstone-5.0.7/src/utils.c

PROJECT_SRCS := \
  analyze/kallsyms_lookup_name.cpp \
  analyze/kallsyms_lookup_name_4_6_0.cpp \
  analyze/kallsyms_lookup_name_6_1_0.cpp \
  analyze/kallsyms_lookup_name_6_1_42.cpp \
  analyze/kallsyms_lookup_name_6_1_60.cpp \
  analyze/kallsyms_lookup_name_6_4_0.cpp \
  analyze/kallsyms_lookup_name_6_12_0.cpp \
  analyze/kernel_symbol_parser.cpp \
  analyze/kernel_version_parser.cpp \
  analyze/symbol_analyze.cpp \
  patch_current_avc_check.cpp \
  patch_avc_denied.cpp \
  patch_audit_log_start.cpp \
  patch_base.cpp \
  patch_do_execve.cpp \
  patch_filldir64.cpp \
  patch_kernel_root.cpp

SRCS_CPP := $(ASMJIT_SRCS) $(PROJECT_SRCS)
SRCS_C   := $(CAPSTONE_SRCS)

OBJS_CPP := $(SRCS_CPP:.cpp=.o)
OBJS_C   := $(SRCS_C:.c=.o)
OBJS     := $(OBJS_CPP) $(OBJS_C)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
