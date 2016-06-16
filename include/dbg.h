#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../include/disas.h"
#include "../include/signal.h"

extern void set_eh(sigact_func func);

#endif
