/*
 * TODO
 *
 * Copyright (C) 2021 zerons
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
#ifndef CLIB_SHM_H_ZFTNPKLB
#define CLIB_SHM_H_ZFTNPKLB

#include "./clib.h"
#include <sys/mman.h>

DECL_BEGIN

struct clib_shm_inner {
	rwlock_t		lock;
	atomic_t		inuse;
	char			data[0];
};

struct clib_shm {
	char			*name;
	struct clib_shm_inner	*inner;
	size_t			datasz;
	int			fd;
};

DECL_END

#endif /* end of include guard: CLIB_SHM_H_ZFTNPKLB */
