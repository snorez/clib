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
#ifndef MODULE_H_AOWIFXRV
#define MODULE_H_AOWIFXRV

#include "../include/clib_utils.h"
#include "../include/clib_list.h"
#include "../include/clib_cmd.h"
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>

DECL_BEGIN

enum clib_module_state {
	CLIB_MODULE_UNLOAD,	/* set when close */
	CLIB_MODULE_LOADED,	/* set when open */
	CLIB_MODULE_FORMAT_ERR,	/* set when sym not found */
};
struct clib_module {
	struct list_head	sibling;
	char			*path;	/* could be absolute path or relative path */
	void			*handle;

	/* set by module itself, find by dlsym module_name_sym */
	char			*module_name;

	/* if not 0, reload/unload should take care of */
	unsigned long		refcount;
	enum clib_module_state	state;
};

#define	CLIB_MODULE_INIT()	\
C_SYM int clib_module_init(struct clib_module *cp, int argc, char *argv[])

#define	CLIB_MODULE_EXIT()	\
C_SYM void clib_module_exit(void)

#define	CLIB_MODULE_NAME(x)	\
char clib_module_name[] = #x;	\
static char __maybe_unused this_module_name[] = #x

#define	CLIB_MODULE_NEEDED0()	\
const char *clib_module_needed[] = {NULL}
#define	CLIB_MODULE_NEEDED1(x)	\
const char *clib_module_needed[] = {#x, NULL}
#define	CLIB_MODULE_NEEDED2(x0, x1)	\
const char *clib_module_needed[] = {#x0, #x1, NULL}
#define	CLIB_MODULE_NEEDED3(x0, x1, x2)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, NULL}
#define	CLIB_MODULE_NEEDED4(x0, x1, x2, x3)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, NULL}
#define	CLIB_MODULE_NEEDED5(x0, x1, x2, x3, x4)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, #x4, NULL}
#define	CLIB_MODULE_NEEDED6(x0, x1, x2, x3, x4, x5)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, NULL}
#define	CLIB_MODULE_NEEDED7(x0, x1, x2, x3, x4, x5, x6)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, NULL}
#define	CLIB_MODULE_NEEDED8(x0, x1, x2, x3, x4, x5, x6, x7)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, #x7, NULL}
#define	CLIB_MODULE_NEEDED9(x0, x1, x2, x3, x4, x5, x6, x7, x8)	\
const char *clib_module_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, #x7, #x8, NULL}

extern int clib_module_load(int argc, char *argv[]);
extern int clib_module_unload(int argc, char *argv[]);
extern int clib_module_reload(int argc, char *argv[]);
extern void clib_module_cleanup(void);
extern void clib_module_print(void);
extern struct list_head *clib_module_get_head(void);
#define	CALL_FUNC_MAX_ARGS	9
extern long clib_module_call_func(const char *module_name,
				  const char *func_name,
				  int argc, ...);

/*
 * sometimes several modules have the same exported symbol, use this macro
 * to call the specific module function, which means you should call with
 * `module_name`__`symbol_name`
 */
#define	CLIB_MODULE_CALL_FUNC_HEAD(module_name,ret_type,func_name,arg_list) \
static __maybe_unused ret_type module_name##__##func_name arg_list

#define	CLIB_MODULE_CALL_FUNC_TAIL(func_name,ret_type,arg_list) \
C_SYM ret_type func_name arg_list

#ifdef CLIB_MODULE_SYMBOL_CONFLICT

#define	CLIB_MODULE_CALL_FUNC0(module_name, func_name, ret_type) \
static __maybe_unused ret_type module_name##__##func_name (void)\
{\
return (ret_type)clib_module_call_func(#module_name,#func_name,0);\
}\
C_SYM ret_type func_name (void)

#define	CLIB_MODULE_CALL_FUNC(module_name, func_name, ret_type, arg_list, argc, ...) \
CLIB_MODULE_CALL_FUNC_HEAD(module_name,ret_type,func_name,arg_list)\
{\
return (ret_type)clib_module_call_func(#module_name,#func_name,argc,##__VA_ARGS__);\
}\
CLIB_MODULE_CALL_FUNC_TAIL(func_name,ret_type,arg_list)

#else	/* !CLIB_MODULE_SYMBOL_CONFLICT */

#define	CLIB_MODULE_CALL_FUNC0(module_name, func_name, ret_type) \
C_SYM ret_type func_name (void);\
static ret_type module_name##__##func_name (void) __attribute__((weakref,alias(#func_name)))

#define	CLIB_MODULE_CALL_FUNC(module_name, func_name, ret_type, arg_list, argc, ...) \
CLIB_MODULE_CALL_FUNC_TAIL(func_name,ret_type,arg_list);\
static ret_type module_name##__##func_name arg_list __attribute__((weakref,alias(#func_name)))

#endif

DECL_END

#endif /* end of include guard: MODULE_H_AOWIFXRV */
