#ifndef SIGNAL_H_EIERSTB0
#define SIGNAL_H_EIERSTB0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include "../include/clib_utils.h"
#include "../include/clib_error.h"
#include "../include/clib_list.h"
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>

DECL_BEGIN

#ifndef sigact_func
typedef void (*sigact_func)(int, siginfo_t *, void *);
#endif

struct clib_timer_signal {
	struct list_head	sibling;
	void			(*sig_action)(int signo, siginfo_t *si, void *arg0);
	void			*arg;
	struct timeval		tv;
	pthread_t		threadid;
	int			timeout;
};

extern int mt_add_timer(int timeout, sigact_func func, void *arg);
extern void mt_del_timer(void);

DECL_END

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
