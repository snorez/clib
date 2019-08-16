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
#ifndef ERROR_H_BHJ5CLAO
#define ERROR_H_BHJ5CLAO

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "../include/clib_utils.h"
#include "../include/clib_dbg.h"

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

extern void mt_print_fini_ncurse(void);
/* for BUG BUG_ON WARN WARN_ON */
#define	BUG()	\
	do {\
	mt_print_fini_ncurse();\
	fprintf(stderr,"***BUG***: %s|%s|%d\n",__FILE__,__FUNCTION__,__LINE__);\
	show_bt();\
	exit(-1);\
	} while (0)
#define	BUG_ON(cond) \
	do {\
		if (unlikely(cond))\
			BUG();\
	} while (0)
#define	WARN()	\
	do {\
	mt_print_fini_ncurse();\
	fprintf(stderr,"***WARN***: %s|%s|%d\n",__FILE__,__FUNCTION__,__LINE__);\
	show_bt();\
	} while (0)
#define	WARN_ON(cond)	\
	do {\
		if (unlikely(cond))\
			WARN();\
	} while (0)

#ifndef MAXLINE
#define MAXLINE 4096
#endif

#ifndef err_fmt
#ifdef __cplusplus
/* in case it is c++11 */
#define err_fmt(a) "[%s:%s:%d] " a, __FILE__, __FUNCTION__, __LINE__
#else
#define err_fmt(a) "[%s:%s:%d] "a, __FILE__, __FUNCTION__, __LINE__
#endif
#endif

extern void _err_msg(const char *fmt, ...);
extern void _err_sys(const char *fmt, ...);
extern void _err_dbg(int has_errno, const char *fmt, ...);
extern void _err_dbg1(int errval, const char *fmt, ...);
extern void _err_dump(const char *fmt, ...);
extern void _err_exit(int has_errno, const char *fmt, ...);
#define	err_msg(fmt, ...) _err_msg(err_fmt(fmt), ##__VA_ARGS__)
#define	err_sys(fmt, ...) _err_sys(err_fmt(fmt), ##__VA_ARGS__)
#define	err_dbg(has_errno, fmt, ...) _err_dbg(has_errno, err_fmt(fmt), ##__VA_ARGS__)
#define	err_dbg1(errval, fmt, ...) _err_dbg1(errval, err_fmt(fmt), ##__VA_ARGS__)
#define	err_dump(fmt, ...) _err_dump(err_fmt(fmt), ##__VA_ARGS__)
#define	err_exit(has_errno, fmt, ...) _err_exit(has_errno, err_fmt(fmt), ##__VA_ARGS__)
#define err_val_ret(has_errno, retval, fmt, ...) \
do {\
	err_dbg(has_errno, fmt, ##__VA_ARGS__);\
	return retval;\
} while(0);
#define err_ptr_ret(has_errno, retval, fmt, ...) \
do {\
	err_dbg(has_errno, fmt, ##__VA_ARGS__);\
	return ERR_PTR(retval);\
} while(0);

extern void set_dbg_mode(int dbg_mode_on);
extern int get_dbg_mode(void);
extern void err_color_on(void);
extern void err_color_off(void);
extern void err_set_color(char *b, char *e);

DECL_END

#endif /* end of include guard: ERROR_H_BHJ5CLAO */
