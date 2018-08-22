#ifndef SIGNAL_H_EIERSTB0
#define SIGNAL_H_EIERSTB0

#ifdef __cplusplus
extern "C" {
#endif

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
#include "../include/clib_error.h"

typedef void (*sigact_func)(int, siginfo_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
