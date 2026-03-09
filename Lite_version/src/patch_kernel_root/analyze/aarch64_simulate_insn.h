#pragma once
#include <string.h>
#include <iostream>

static int sign_extend32(unsigned int value, int index) {
	uint8_t shift = 31 - index;
	return (int)(value << shift) >> shift;
}
#define bbl_displacement(insn)		\
	sign_extend32(((insn) & 0x3ffffff) << 2, 27)

#define bcond_displacement(insn)	\
	sign_extend32(((insn >> 5) & 0x7ffff) << 2, 20)

#define cbz_displacement(insn)	\
	sign_extend32(((insn >> 5) & 0x7ffff) << 2, 20)

#define tbz_displacement(insn)	\
	sign_extend32(((insn >> 5) & 0x3fff) << 2, 15)

#define ldr_displacement(insn)	\
	sign_extend32(((insn >> 5) & 0x7ffff) << 2, 20)
