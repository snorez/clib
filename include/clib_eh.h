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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <ucontext.h>
#include <link.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include "../include/clib_utils.h"
#include "../include/clib_atomic.h"
#include "../include/clib_disas.h"
#include "../include/clib_elf.h"

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

#define	BUILD_BUG_ON(cond,msg) static_assert(!(cond),msg)

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

extern void err_color_on(void);
extern void err_color_off(void);
extern void err_set_color(char *b, char *e);

#ifndef SIGACT_FUNC
#define	SIGACT_FUNC
typedef int (*clib_sigfunc)(int, siginfo_t *, void *);
#endif

extern int eh_mode;
enum eh_mode_shift {
	EH_M_DBG_SHIFT = 0,
	EH_M_CLEAN_SHIFT,
	EH_M_MT_SHIFT,
};
#define	EH_M_DEF	0
#define	EH_M_DBG	(1<<EH_M_DBG_SHIFT)
#define	EH_M_CLEAN	(1<<EH_M_CLEAN_SHIFT)
#define	EH_M_MT		(1<<EH_M_MT_SHIFT)

struct eh_list {
	struct list_head	sibling;
	clib_sigfunc		cb;
	int			signo;
	int			for_clean_mode;
	int			exclusive;
};

extern void clib_dladdr_start(struct list_head *head, uint8_t *bits);
extern void clib_dladdr(void *addr, Dl_info *info);
extern void clib_dladdr_end(void);
extern void set_eh(struct eh_list *new_eh);
extern void set_eh_mode(int mode);
extern void show_bt(void);

#ifndef xmalloc
#define	xmalloc malloc
#endif

static inline void enable_eh_mode(int pos)
{
	eh_mode |= (1<<pos);
}

static inline void disable_eh_mode(int pos)
{
	eh_mode &= ~(1<<pos);
}

static inline void enable_dbg_mode(void)
{
	enable_eh_mode(EH_M_DBG_SHIFT);
}

static inline void disable_dbg_mode(void)
{
	disable_eh_mode(EH_M_DBG_SHIFT);
}

static inline void enable_clean_mode(void)
{
	enable_eh_mode(EH_M_CLEAN_SHIFT);
}

static inline void disable_clean_mode(void)
{
	disable_eh_mode(EH_M_CLEAN_SHIFT);
}

static inline void enable_mt_mode(void)
{
	enable_eh_mode(EH_M_MT_SHIFT);
}

static inline void disable_mt_mode(void)
{
	disable_eh_mode(EH_M_MT_SHIFT);
}

static inline struct eh_list *eh_list_new(clib_sigfunc func, int signo,
					  int for_clean_mode, int exclusive)
{
	struct eh_list *_new;
	_new = (struct eh_list *)xmalloc(sizeof(*_new));
	memset(_new, 0, sizeof(*_new));

	_new->cb = func;
	_new->signo = signo;
	_new->for_clean_mode = for_clean_mode;
	_new->exclusive = exclusive;
	return _new;
}

/*
 * for multi-thread backtrace, we maintain a list for each pthread_id.
 * Functions should call the given interfaces to push/pop the __FUNCTION__.
 */
static inline void clib_pthread_stack(pthread_attr_t *attr, pthread_t id,
					void **top, void **bot)
{
	size_t sz;
	*top = NULL;
	*bot = NULL;

	if (!pthread_attr_getstacksize(attr, &sz)) {
		*top = (void *)id;
		*bot = (void *)((size_t)*top - sz);
	}

	return;
}

static inline void clib_pthread_current_stack(pthread_attr_t *attr,
						void **top, void **bot)
{
	clib_pthread_stack(attr, pthread_self(), top, bot);
	return;
}

static inline int clib_pthread_instack(void *top, void *bot, void *addr)
{
	if (((addr > top) && (addr < bot)) ||
		((addr < top) && (addr > bot)))
		return 1;
	else
		return 0;
}

#define	DEFAULT_BT_COUNT	((size_t)1024)
struct clib_dbg_mt {
	struct list_head	sibling;
	pthread_t		tid;
	size_t			bt_total;
	size_t			bt_idx;
	char			**bt;
};

extern struct list_head clib_dbg_mt_head;
extern rwlock_t clib_dbg_mt_lock;
static inline struct clib_dbg_mt *clib_dbg_mt_new(size_t count)
{
	struct clib_dbg_mt *_new;
	_new = (struct clib_dbg_mt *)xmalloc(sizeof(*_new));
	_new->bt = (char **)xmalloc(count * sizeof(char *));

	_new->tid = pthread_self();
	_new->bt_total = count;
	_new->bt_idx = 0;

	return _new;
}

static inline void clib_dbg_mt_free(struct clib_dbg_mt *n)
{
	free(n->bt);
	free(n);
}

static inline void clib_dbg_mt_insert(struct clib_dbg_mt *n)
{
	write_lock(&clib_dbg_mt_lock);
	list_add_tail(&n->sibling, &clib_dbg_mt_head);
	write_unlock(&clib_dbg_mt_lock);
}

static inline void clib_dbg_mt_remove(struct clib_dbg_mt *n)
{
	write_lock(&clib_dbg_mt_lock);
	list_del(&n->sibling);
	write_unlock(&clib_dbg_mt_lock);
}

static inline struct clib_dbg_mt *clib_dbg_mt_find(void)
{
	struct clib_dbg_mt *tmp;
	struct clib_dbg_mt *target = NULL;
	pthread_t target_tid = pthread_self();

	read_lock(&clib_dbg_mt_lock);
	list_for_each_entry(tmp, &clib_dbg_mt_head, sibling) {
		if (!pthread_equal(target_tid, tmp->tid))
			continue;
		target = tmp;
		break;
	}
	read_unlock(&clib_dbg_mt_lock);

	return target;
}

static inline void clib_dbg_mt_expand(struct clib_dbg_mt *t)
{
	size_t oldcnt, newcnt;

	oldcnt = t->bt_total;
	newcnt = oldcnt + DEFAULT_BT_COUNT;

	char **newbt;
	newbt = (char **)xmalloc(newcnt * sizeof(char *));
	memcpy(newbt, t->bt, t->bt_idx * sizeof(char *));

	free(t->bt);
	t->bt = newbt;
	t->bt_total = newcnt;
}

static inline void clib_dbg_mt_push(struct clib_dbg_mt *t, const char *name)
{
	if (t->bt_idx >= t->bt_total)
		clib_dbg_mt_expand(t);

	t->bt[t->bt_idx] = (char *)name;
	t->bt_idx++;
}

static inline void clib_dbg_mt_pop(struct clib_dbg_mt *t,
					const char *name, int *flag)
{
	*flag = 0;

	if (!t->bt_idx)
		return;

	size_t last_idx = t->bt_idx - 1;
	if (t->bt[last_idx] == (char *)name) {
		t->bt_idx = last_idx;
	} else {
		*flag = 1;
	}
}

static inline void clib_dbg_func_enter(const char *funcname)
{
	enable_mt_mode();

	struct clib_dbg_mt *t;
	t = clib_dbg_mt_find();
	if (!t) {
		t = clib_dbg_mt_new(DEFAULT_BT_COUNT);
		clib_dbg_mt_insert(t);
	}

	clib_dbg_mt_push(t, funcname);
}

static inline void clib_dbg_func_exit(const char *funcname)
{
	struct clib_dbg_mt *t;
	t = clib_dbg_mt_find();
	if (!t)
		return;

	int wrong;
	clib_dbg_mt_pop(t, funcname, &wrong);

	if (wrong || (!t->bt_idx)) {
		clib_dbg_mt_remove(t);
		clib_dbg_mt_free(t);
	}

	if (list_empty(&clib_dbg_mt_head))
		disable_mt_mode();
}

static inline int clib_dbg_func_check(void)
{
	return !!clib_dbg_mt_find();
}


#ifdef HAVE_CLIB_DBG_FUNC
#define	CLIB_DBG_FUNC_ENTER()	\
	do {\
		clib_dbg_func_enter(__FUNCTION__);\
	} while (0);

#define	CLIB_DBG_FUNC_EXIT()	\
	do {\
		clib_dbg_func_exit(__FUNCTION__);\
	} while (0);

#else	/* !HAVE_CLIB_DBG_FUNC */

#define	CLIB_DBG_FUNC_ENTER()	((void)0)
#define	CLIB_DBG_FUNC_EXIT()	((void)0)

#endif

DECL_END


#endif /* end of include guard: ERROR_H_BHJ5CLAO */
