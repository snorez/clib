#ifndef __DISAH__
#define __DISAH__

#include <stdint.h>
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

#define		X86_X64_OPCODE_MAXLEN		15

extern int disas_single(int arch, int mode, void *addr);

#endif
