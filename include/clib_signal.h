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
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>

DECL_BEGIN

typedef void (*sigact_func)(int, siginfo_t *, void *);

DECL_END

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
