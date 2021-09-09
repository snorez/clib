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
#include "../include/clib_rwpool.h"

static struct clib_rw_pool *clib_rw_pool_new(void (*free_pool_elem)(void *))
{
	void *addr = NULL;
	struct clib_rw_pool *_new = NULL;

	addr = malloc(OBJPOOL_CNT * sizeof(void *));
	if (unlikely(!addr)) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(addr, 0, OBJPOOL_CNT * sizeof(void *));

	_new = (struct clib_rw_pool *)malloc(sizeof(*_new));
	if (unlikely(!_new)) {
		err_dbg(0, "malloc err");
		free(addr);
		return NULL;
	}
	memset(_new, 0, sizeof(*_new));

	mutex_init(&_new->lock);

	_new->pool_addr = addr;
	_new->free_pool_elem = free_pool_elem;

	return _new;
}

static void clib_rw_pool_free(struct clib_rw_pool *p)
{
	void **start = (void **)p->pool_addr;

	if (p->free_pool_elem) {
		for (size_t i = 0; i < OBJPOOL_CNT; i++) {
			if (!start[i])
				continue;
			p->free_pool_elem(start[i]);
		}
	}
	free(p->pool_addr);
	free(p);
}

static void **clib_rw_pool_write_find(struct clib_rw_pool *pool)
{
	void **start = (void **)pool->pool_addr;
	size_t i = 0;

	for (i = pool->writer_idx; i < OBJPOOL_CNT; i++) {
		if (!start[i]) {
			pool->writer_idx = i + 1;
			return &start[i];
		}
	}

	for (i = 0; i < pool->writer_idx; i++) {
		if (!start[i]) {
			pool->writer_idx = i + 1;
			return &start[i];
		}
	}

	return NULL;
}

static void **clib_rw_pool_read_find(struct clib_rw_pool *pool)
{
	void **start = (void **)pool->pool_addr;
	size_t i = 0;

	for (i = pool->reader_idx; i < OBJPOOL_CNT; i++) {
		if (start[i]) {
			pool->reader_idx = i + 1;
			return &start[i];
		}
	}

	for (i = 0; i < pool->reader_idx; i++) {
		if (start[i]) {
			pool->reader_idx = i + 1;
			return &start[i];
		}
	}

	return NULL;
}

#ifndef CONFIG_USLEEP_TIME
#define	USLEEP_TIME	3000
#else
#define	USLEEP_TIME	(CONFIG_USLEEP_TIME)
#endif

int clib_rw_pool_push(struct clib_rw_job *job, void *obj)
{
	int ret = 0;
	void **addr;
	struct clib_rw_pool *pool = job->pool;

	mutex_lock(&pool->lock);
	while (1) {
		if (job->status != JOB_STATUS_RUNNING) {
			ret = -1;
			break;
		}

		addr = clib_rw_pool_write_find(pool);
		if (addr) {
			*addr = obj;
			break;
		}

		mutex_unlock(&pool->lock);
		usleep(USLEEP_TIME);
		mutex_lock(&pool->lock);
	}
	mutex_unlock(&pool->lock);

	return ret;
}

void *clib_rw_pool_pop(struct clib_rw_job *job)
{
	void **addr;
	void *ret = NULL;
	struct clib_rw_pool *pool = job->pool;
	int loop_one_more = 0;

	mutex_lock(&pool->lock);
	while (1) {
		if (job->status != JOB_STATUS_RUNNING) {
			break;
		}

		addr = clib_rw_pool_read_find(pool);
		if (addr) {
			ret = *addr;
			*addr = NULL;
			break;
		}

		if (clib_rw_all_writer_done(job)) {
			if (loop_one_more) {
				break;
			}
			loop_one_more = 1;
		}

		mutex_unlock(&pool->lock);
		usleep(USLEEP_TIME);
		mutex_lock(&pool->lock);
	}
	mutex_unlock(&pool->lock);

	return ret;
}

static void *writer_thread(void *arg)
{
#if 0
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif

	struct clib_rw_job *job = (struct clib_rw_job *)arg;
	struct clib_rw_thread *t = rw_thread(job, 0);
	BUG_ON(!t);

	job->writer(job->write_arg, job);

	t->done = 1;

	return (void *)0;
}

static void *reader_thread(void *arg)
{
#if 0
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif

	struct clib_rw_job *job = arg;
	struct clib_rw_thread *t = rw_thread(job, 1);
	BUG_ON(!t);

	job->reader(job->read_arg, job);

	t->done = 1;

	return (void *)0;
}

struct clib_rw_job *clib_rw_job_new(void (*writer)(void *, struct clib_rw_job *),
				    void *write_arg,
				    int writer_cnt,
				    void (*reader)(void *, struct clib_rw_job *),
				    void *read_arg,
				    int reader_cnt,
				    void (*free_pool_elem)(void *))
{
	if ((writer_cnt <= 0) || (reader_cnt <= 0)) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	struct clib_rw_job *_new;
	size_t malloc_len = sizeof(*_new);
	malloc_len += sizeof(_new->threads[0]) * (writer_cnt + reader_cnt);
	_new = (struct clib_rw_job *)malloc(malloc_len);
	if (!_new) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(_new, 0, malloc_len);

	_new->pool = clib_rw_pool_new(free_pool_elem);
	if (!_new->pool) {
		err_dbg(0, "clib_rw_pool_new err");
		free(_new);
		return NULL;
	}

	_new->writer = writer;
	_new->write_arg = write_arg;
	_new->writer_cnt = writer_cnt;
	_new->reader = reader;
	_new->read_arg = read_arg;
	_new->reader_cnt = reader_cnt;

	return _new;
}

void clib_rw_job_free(struct clib_rw_job *job)
{
	if (job) {
		clib_rw_pool_free(job->pool);
		free(job);
	}
}

int clib_rw_job_run(struct clib_rw_job *job)
{
	int err = 0;

	/* change the status first */
	job->status = JOB_STATUS_RUNNING;

	for (int i = 0; i < job->writer_cnt; i++) {
		err = pthread_create(&job->threads[i].tid, NULL,
				     writer_thread, (void *)job);
		if (err) {
			err_dbg(0, "pthread_create err");
			return -1;
		}
	}

	for (int i = job->writer_cnt; i < (job->writer_cnt + job->reader_cnt); i++) {
		err = pthread_create(&job->threads[i].tid, NULL,
				     reader_thread, (void *)job);
		if (err) {
			err_dbg(0, "pthread_create err, should kill writer thread");
			return -1;
		}
	}

	return 0;
}

void clib_rw_job_term(struct clib_rw_job *job)
{
	job->status = JOB_STATUS_TERM;

	for (int i = 0; i < (job->writer_cnt + job->reader_cnt); i++) {
		if (!job->threads[i].tid)
			continue;
		pthread_join(job->threads[i].tid, NULL);
	}
}
