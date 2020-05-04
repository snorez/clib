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
#ifndef SIGNAL_H_EIERSTB0
#define SIGNAL_H_EIERSTB0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>
#include "../include/clib_utils.h"
#include "../include/clib_eh.h"
#include "../include/clib_list.h"

DECL_BEGIN

#ifndef CLIB_TIMER_FUNC
#define	CLIB_TIMER_FUNC
typedef void (*clib_timer_func)(int signo, siginfo_t *si, void *arg, int is_last);
#endif

struct clib_timer {
	struct list_head	sibling;
	clib_timer_func		sig_action;
	void			*arg;
	struct timeval		tv;
	pthread_t		threadid;
	int			timer_id;
	int			timeout;	/* in second */
};

extern int mt_add_timer(int timeout, clib_timer_func func, void *arg,
			int timer_id, int imm);
extern void mt_del_timer(int timer_id);

DECL_END

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
