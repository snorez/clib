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
#ifndef CLIB_OBJPOOL_H_Y1M3NESU
#define CLIB_OBJPOOL_H_Y1M3NESU

#include "../include/clib.h"

DECL_BEGIN

/*
 * each object is a pointer to a user-defined object
 * if this object is NULL, it is available
 */
#define	OBJPOOL_CNT	1024

enum job_status {
	JOB_STATUS_WAIT = 0,
	JOB_STATUS_RUNNING = 1,
	JOB_STATUS_TERM = 2,
};

struct clib_rw_thread {
	pthread_t		tid;
	char			done;
};

struct clib_rw_pool {
	void			(*free_pool_elem)(void *);
	void			*pool_addr;
	size_t			reader_idx;
	size_t			writer_idx;
	mutex_t			lock;
	atomic_t		writer;
};

struct clib_rw_job {
	struct clib_rw_pool	*pool;
	void			(*writer)(void *arg, struct clib_rw_job *job);
	void			*write_arg;
	void			(*reader)(void *arg, struct clib_rw_job *job);
	void			*read_arg;

	int			writer_cnt;
	int			reader_cnt;

	int			status;

	struct clib_rw_thread	threads[0];	/* minimum threads */
};

/* these two are for job_writer and job_reader */
extern int clib_rw_pool_push(struct clib_rw_job *job, void *obj);
extern void *clib_rw_pool_pop(struct clib_rw_job *job);

extern struct clib_rw_job *clib_rw_job_new(void (*writer)(void *, struct clib_rw_job *),
					   void *write_arg,
					   int writer_cnt,
					   void (*reader)(void *, struct clib_rw_job *),
					   void *read_arg,
					   int reader_cnt,
					   void (*free_pool_elem)(void *));
extern void clib_rw_job_free(struct clib_rw_job *job);
extern int clib_rw_job_run(struct clib_rw_job *job);
extern void clib_rw_job_term(struct clib_rw_job *job);

static inline struct clib_rw_thread *rw_thread(struct clib_rw_job *job, int reader)
{
	int idx_b = 0, idx_e = job->writer_cnt;
	if (reader) {
		idx_b = job->writer_cnt;
		idx_e = job->writer_cnt + job->reader_cnt;
	}

	for (; idx_b < idx_e; idx_b++) {
		if (pthread_equal(job->threads[idx_b].tid, pthread_self())) {
			return &job->threads[idx_b];
		}
	}

	return NULL;
}

static inline int clib_rw_all_writer_done(struct clib_rw_job *job)
{
	for (int i = 0; i < job->writer_cnt; i++) {
		if (!job->threads[i].tid) {
			continue;
		}

		if (!job->threads[i].done)
			return 0;
	}

	return 1;
}

static inline int clib_rw_all_reader_done(struct clib_rw_job *job)
{
	for (int i = job->writer_cnt; i < (job->writer_cnt + job->reader_cnt); i++) {
		if (!job->threads[i].tid) {
			continue;
		}

		if (!job->threads[i].done)
			return 0;
	}

	return 1;
}

static inline int clib_rw_all_thread_done(struct clib_rw_job *job)
{
	return clib_rw_all_writer_done(job) && clib_rw_all_reader_done(job);
}

DECL_END

#endif /* end of include guard: CLIB_OBJPOOL_H_Y1M3NESU */
