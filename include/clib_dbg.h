/*
 * TODO
 * Copyright (C) 2018  zerons
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
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

#ifndef xmalloc
#define	xmalloc malloc
#endif

static inline struct eh_list *eh_list_new(sigact_func func)
{
	struct eh_list *_new;
	_new = (struct eh_list *)xmalloc(sizeof(*_new));
	memset(_new, 0, sizeof(*_new));

	_new->cb = func;
	return _new;
}

DECL_END

#endif /* end of include guard: DBG_H_VSLA5ZHT */
