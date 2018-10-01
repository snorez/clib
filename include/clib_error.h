#ifndef ERROR_H_BHJ5CLAO
#define ERROR_H_BHJ5CLAO

#include "../include/clib_utils.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

DECL_BEGIN

/*
 * these code come from linux kernel include/linux/err.h
 */
#define	MAX_ERRNO	4095
#define	IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline int IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline int IS_ERR_OR_NULL(const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

extern void show_bt(void);
/* for BUG BUG_ON WARN WARN_ON */
#define	BUG()	\
	do {\
	fprintf(stderr,"***BUG***: %s|%s|%d\n",__FILE__,__FUNCTION__,__LINE__);\
	show_bt();\
	exit(-1);\
	} while (0)
#define	BUG_ON(cond) \
	do {\
		if (cond)\
			BUG();\
	} while (0)
#define	WARN()	\
	do {\
	fprintf(stderr,"***WARN***: %s|%s|%d\n",__FILE__,__FUNCTION__,__LINE__);\
	show_bt();\
	} while (0)
#define	WARN_ON(cond)	\
	do {\
		if (cond)\
			WARN();\
	} while (0)

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
#define err_retval(has_errno, retval, fmt, ...) \
do {\
	err_dbg(has_errno, fmt, ##__VA_ARGS__);\
	return retval;\
} while(0);
#define err_ret(has_errno, retval, fmt, ...) \
do {\
	err_dbg(has_errno, fmt, ##__VA_ARGS__);\
	errno = (retval < 0) ? -retval : retval;\
	return -1;\
} while(0);
#define err_ptr_ret(has_errno, retval, fmt, ...) \
do {\
	err_dbg(has_errno, fmt, ##__VA_ARGS__);\
	errno = (retval < 0) ? -retval : retval;\
	return NULL;\
} while(0);
extern void set_dbg_mode(int dbg_mode_on);
extern int get_dbg_mode(void);
extern void err_color_on(void);
extern void err_color_off(void);
extern void err_set_color(char *b, char *e);

DECL_END

#endif /* end of include guard: ERROR_H_BHJ5CLAO */
