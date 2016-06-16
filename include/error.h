#ifndef __ERROR_H__
#define __ERROR_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifndef MAXLINE
#define MAXLINE 4096
#endif

#ifndef err_fmt
#define err_fmt(a) "%s|%s|%d: "a, __FILE__, __FUNCTION__, __LINE__
#endif

extern void err_msg(const char *fmt, ...);
extern void err_sys(const char *fmt, ...);
extern void err_dbg(int has_errno, const char *fmt, ...);
extern void err_dump(const char *fmt, ...);
extern void err_exit(int has_errno, const char *fmt, ...);
extern int err_ret(int has_errno, int retval, const char *fmt, ...);
extern void set_dbg_mode(int dbg_mode_on);

#endif
