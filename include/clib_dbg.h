#ifndef DBG_H_VSLA5ZHT
#define DBG_H_VSLA5ZHT

#include "../include/clib_utils.h"
#include "../include/clib_atomic.h"
#include "../include/clib_disas.h"
#include "../include/clib_signal.h"
#include "../include/clib_elf.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

DECL_BEGIN
extern void clib_dladdr_start(struct list_head *head, uint8_t *bits);
extern void clib_dladdr(void *addr, Dl_info *info);
extern void clib_dladdr_end(void);
extern void set_eh(sigact_func func);
extern void show_bt(void);

DECL_END

#endif /* end of include guard: DBG_H_VSLA5ZHT */
