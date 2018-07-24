#ifndef SIGNAL_H_EIERSTB0
#define SIGNAL_H_EIERSTB0

#define _GNU_SOURCE
#define __USE_GNU
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include "../include/error.h"

typedef void (*sigact_func)(int, siginfo_t *, void *);

#endif /* end of include guard: SIGNAL_H_EIERSTB0 */
