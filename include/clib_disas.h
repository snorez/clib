#ifndef DISAS_H_QWXBDHCJ
#define DISAS_H_QWXBDHCJ

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

#define		X86_X64_OPCODE_MAXLEN		15

extern int disas_single(int arch, int mode, void *addr);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: DISAS_H_QWXBDHCJ */
