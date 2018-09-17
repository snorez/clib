#ifndef DISAS_H_QWXBDHCJ
#define DISAS_H_QWXBDHCJ

#include "../include/clib_utils.h"
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif
#include <stdint.h>

DECL_BEGIN

#define		X86_X64_OPCODE_MAXLEN		15

extern int disas_single(int arch, int mode, void *addr);

DECL_END

#endif /* end of include guard: DISAS_H_QWXBDHCJ */
