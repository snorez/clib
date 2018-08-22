#ifndef DBG_H_VSLA5ZHT
#define DBG_H_VSLA5ZHT

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../include/clib_disas.h"
#include "../include/clib_signal.h"

extern void set_eh(sigact_func func);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: DBG_H_VSLA5ZHT */
