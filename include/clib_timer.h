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
#include "../include/clib_error.h"
#include "../include/clib_list.h"

DECL_BEGIN

#ifndef CLIB_TIMER_FUNC
#define	CLIB_TIMER_FUNC
typedef void (*clib_timer_func)(int, siginfo_t *, void *, int);
#endif

struct clib_timer {
	struct list_head	sibling;
	clib_timer_func		sig_action;
	void			*arg;
	struct timeval		tv;
	pthread_t		threadid;
	int			timeout;	/* in second */
};

extern int mt_add_timer(int timeout, clib_timer_func func, void *arg);
extern void mt_del_timer(void);

DECL_END

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
