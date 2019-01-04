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
#ifndef CLIB_THREADPOOL_H_Y0XQYN2O
#define CLIB_THREADPOOL_H_Y0XQYN2O

#include "../include/clib.h"

DECL_BEGIN

#define	CLIB_THREADPOOL_MAX	0x30
#define	CLIB_THREAD_ARG_MAX	0x10
struct clib_mt_pool {
	pthread_t	tid;
	atomic_t	in_use;
	int		ret;
	long		arg[CLIB_THREAD_ARG_MAX];
	void		*data;
};

static inline void clib_mt_pool_init(struct clib_mt_pool *pool)
{
	memset(pool, 0, sizeof(*pool));
}

extern struct clib_mt_pool *clib_mt_pool_new(int thread_cnt);
extern struct clib_mt_pool *clib_mt_pool_get(struct clib_mt_pool *pool,
						int thread_cnt);
extern void clib_mt_pool_put(struct clib_mt_pool *pool);
extern void clib_mt_pool_wait_all(struct clib_mt_pool *pool, int thread_cnt);
extern void clib_mt_pool_free(struct clib_mt_pool *pool);

DECL_END

#endif /* end of include guard: CLIB_THREADPOOL_H_Y0XQYN2O */
