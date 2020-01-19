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
#ifndef DBG_H_VSLA5ZHT
#define DBG_H_VSLA5ZHT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
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

#ifndef SIGACT_FUNC
#define	SIGACT_FUNC
typedef int (*clib_sigfunc)(int, siginfo_t *, void *);
#endif

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

extern int dbg_mt_mode;
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
	dbg_mt_mode = 1;

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
		dbg_mt_mode = 0;
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

#endif /* end of include guard: DBG_H_VSLA5ZHT */
