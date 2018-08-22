#ifndef ERROR_H_BHJ5CLAO
#define ERROR_H_BHJ5CLAO

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifndef MAXLINE
#define MAXLINE 4096
#endif

#ifndef err_fmt
#ifdef __cplusplus
/* in case it is c++11 */
#define err_fmt(a) "%s|%s|%d: " a, __FILE__, __FUNCTION__, __LINE__
#else
#define err_fmt(a) "%s|%s|%d: "a, __FILE__, __FUNCTION__, __LINE__
#endif
#endif

extern void err_msg(const char *fmt, ...);
extern void err_sys(const char *fmt, ...);
extern void err_dbg(int has_errno, const char *fmt, ...);
extern void err_dbg1(int errval, const char *fmt, ...);
extern void err_dump(const char *fmt, ...);
extern void err_exit(int has_errno, const char *fmt, ...);
extern int err_ret(int has_errno, int retval, const char *fmt, ...);
extern void set_dbg_mode(int dbg_mode_on);
extern int get_dbg_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: ERROR_H_BHJ5CLAO */
