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
#define	OBJPOOL_MAX	0x100000
#define	OBJPOOL_DEF	0x10000
struct clib_rw_pool {
	void		*pool_addr;
	size_t		obj_cnt;
	size_t		reader_idx;
	size_t		writer_idx;
	atomic_t	writer;
	lock_t		lock;
};

struct clib_rw_pool_job {
	struct clib_rw_pool	*pool;
	void		(*writer)(void *arg, struct clib_rw_pool *pool);
	void		*write_arg;
	void		(*reader)(void *arg, struct clib_rw_pool *pool);
	void		*read_arg;
};

/* these two are for job_writer and job_reader */
extern void clib_rw_pool_push(struct clib_rw_pool *pool, void *obj);
extern void *clib_rw_pool_pop(struct clib_rw_pool *pool);

extern struct clib_rw_pool_job *clib_rw_pool_job_new(size_t obj_cnt,
					void (writer)(void *, struct clib_rw_pool *),
					void *write_arg,
					void (reader)(void *, struct clib_rw_pool *),
					void *read_arg);
extern void clib_rw_pool_job_free(struct clib_rw_pool_job *job);
extern int clib_rw_pool_job_run(struct clib_rw_pool_job *job);

DECL_END

#endif /* end of include guard: CLIB_OBJPOOL_H_Y1M3NESU */
