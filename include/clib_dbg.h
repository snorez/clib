#ifndef DBG_H_VSLA5ZHT
#define DBG_H_VSLA5ZHT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>
#include "../include/clib_utils.h"
#include "../include/clib_atomic.h"
#include "../include/clib_disas.h"
#include "../include/clib_elf.h"

DECL_BEGIN

#ifndef SIGACT_FUNC
#define	SIGACT_FUNC
typedef void (*sigact_func)(int, siginfo_t *, void *);
#endif

struct eh_list {
	struct list_head	sibling;
	sigact_func		cb;
};

extern void clib_dladdr_start(struct list_head *head, uint8_t *bits);
extern void clib_dladdr(void *addr, Dl_info *info);
extern void clib_dladdr_end(void);
extern void set_eh(struct eh_list *new_eh);
extern void show_bt(void);

static inline struct eh_list *eh_list_new(sigact_func func)
{
	struct eh_list *_new;
	_new = (struct eh_list *)malloc_s(sizeof(*_new));

	_new->cb = func;
	return _new;
}

DECL_END

#endif /* end of include guard: DBG_H_VSLA5ZHT */
