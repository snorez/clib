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

static struct clib_rw_pool *clib_rw_pool_new(size_t obj_cnt)
{
	void *addr = NULL;
	struct clib_rw_pool *_new = NULL;

	if (unlikely(obj_cnt > OBJPOOL_MAX)) {
		err_dbg(0, "size check err");
		return NULL;
	}

	addr = malloc(obj_cnt * sizeof(void *));
	if (unlikely(!addr)) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(addr, 0, obj_cnt * sizeof(void *));

	_new = (struct clib_rw_pool *)malloc(sizeof(*_new));
	if (unlikely(!_new)) {
		err_dbg(0, "malloc err");
		free(addr);
		return NULL;
	}
	memset(_new, 0, sizeof(*_new));

	_new->pool_addr = addr;
	_new->obj_cnt = obj_cnt;
	return _new;
}

static void clib_rw_pool_free(struct clib_rw_pool *p)
{
	free(p->pool_addr);
	free(p);
}

static void **clib_rw_pool_write_find(struct clib_rw_pool *pool)
{
	void **start = (void **)pool->pool_addr;
	size_t i = 0;

	for (i = pool->writer_idx; i < pool->obj_cnt; i++) {
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

	for (i = pool->reader_idx; i < pool->obj_cnt; i++) {
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

#define	USLEEP_TIME	3000
void clib_rw_pool_push(struct clib_rw_pool *pool, void *obj)
{
	void **addr;

	mutex_lock(&pool->lock);
	while (1) {
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
}

#define	LOOP_MORE_TIMES	0x1
void *clib_rw_pool_pop(struct clib_rw_pool *pool)
{
	void **addr;
	void *ret = NULL;
	int loop_more = 0;

	mutex_lock(&pool->lock);
	while (1) {
		addr = clib_rw_pool_read_find(pool);
		if (addr) {
			ret = *addr;
			*addr = NULL;
			break;
		}

		mutex_unlock(&pool->lock);
		usleep(USLEEP_TIME);
		mutex_lock(&pool->lock);
		if (!atomic_read(&pool->writer)) {
			if (loop_more >= LOOP_MORE_TIMES)
				break;
			loop_more++;
			continue;
		}
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

	struct clib_rw_pool_job *job = arg;
	job->writer(job->write_arg, job->pool);
	return (void *)0;
}

static void *reader_thread(void *arg)
{
#if 0
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif

	struct clib_rw_pool_job *job = arg;
	job->reader(job->read_arg, job->pool);
	return (void *)0;
}

struct clib_rw_pool_job *clib_rw_pool_job_new(size_t obj_cnt,
					void (writer)(void *, struct clib_rw_pool *),
					void *write_arg,
					void (reader)(void *, struct clib_rw_pool *),
					void *read_arg)
{
	struct clib_rw_pool_job *_new;
	_new = (struct clib_rw_pool_job *)malloc(sizeof(*_new));
	if (!_new) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(_new, 0, sizeof(*_new));

	_new->pool = clib_rw_pool_new(obj_cnt);
	if (!_new->pool) {
		err_dbg(0, "clib_rw_pool_new err");
		free(_new);
		return NULL;
	}

	_new->writer = writer;
	_new->write_arg = write_arg;
	_new->reader = reader;
	_new->read_arg = read_arg;
	return _new;
}

void clib_rw_pool_job_free(struct clib_rw_pool_job *job)
{
	if (job) {
		clib_rw_pool_free(job->pool);
		free(job);
	}
}

int clib_rw_pool_job_run(struct clib_rw_pool_job *job)
{
	int err = 0;
	pthread_t tid_writer;
	pthread_t tid_reader;

	/* setup threads */
	err = pthread_create(&tid_writer, NULL, writer_thread, (void *)job);
	if (err) {
		err_dbg(0, "pthread_create err");
		return -1;
	}
	atomic_inc(&job->pool->writer);
	usleep(USLEEP_TIME);

	err = pthread_create(&tid_reader, NULL, reader_thread, (void *)job);
	if (err) {
		err_dbg(0, "pthread_create err, kill writer thread");
		BUG();
		return -1;
	}

	/* wait for all thread */
	pthread_join(tid_writer, NULL);
	atomic_dec(&job->pool->writer);

	pthread_join(tid_reader, NULL);

	return 0;
}
