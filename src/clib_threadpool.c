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
#include "../include/clib_threadpool.h"

struct clib_mt_pool *clib_mt_pool_new(int thread_cnt)
{
	if ((thread_cnt < 0) || (thread_cnt > CLIB_THREADPOOL_MAX)) {
		err_dbg(0, err_fmt("thread_cnt invalid"));
		return NULL;
	}

	struct clib_mt_pool *_new;
	_new = (struct clib_mt_pool *)malloc(sizeof(*_new) * thread_cnt);
	if (!_new) {
		err_dbg(0, err_fmt("malloc err"));
		return NULL;
	}

	for (int i = 0; i < thread_cnt; i++) {
		clib_mt_pool_init(&_new[i]);
	}

	return _new;
}

struct clib_mt_pool *clib_mt_pool_get(struct clib_mt_pool *pool, int thread_cnt)
{
	while (1) {
		for (int i = 0; i < thread_cnt; i++) {
			if (!atomic_read(&pool[i].in_use)) {
				atomic_set(&pool[i].in_use, 1);
				return &pool[i];
			}
		}
	}
}

void clib_mt_pool_put(struct clib_mt_pool *pool)
{
	atomic_set(&pool->in_use, 0);
}

void clib_mt_pool_wait_all(struct clib_mt_pool *pool, int thread_cnt)
{
	for (int i = 0; i < thread_cnt; i++) {
		if (pool[i].tid)
			pthread_join(pool[i].tid, NULL);
		long in_use = atomic_read(&pool[i].in_use);
		if (!in_use) {
			continue;
		} else {
			i = -1;
			usleep(1000*3);
			continue;
		}
	}
}

void clib_mt_pool_free(struct clib_mt_pool *pool)
{
	free(pool);
}
