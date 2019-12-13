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
#ifndef CLIB_MM_H_PR1CMVVD
#define CLIB_MM_H_PR1CMVVD

/*
 * this is for using continuous memory area. without any free action
 * there are two kind of memory: not-expanded, expandable
 */
#include "../include/clib.h"
#include <sys/mman.h>

DECL_BEGIN

#ifndef CONFIG_CLIB_MM_DESC_LEN
#define	CLIB_MM_DESC_LEN	8
#else
#define	CLIB_MM_DESC_LEN	(CONFIG_CLIB_MM_DESC_LEN)
#endif

#ifndef CONFIG_CLIB_MM_MMAP_BLKSZ
#define	CLIB_MM_MMAP_BLKSZ	(64*1024*1024)
#else
#define	CLIB_MM_MMAP_BLKSZ	(CONFIG_CLIB_MM_MMAP_BLKSZ)
#endif

struct clib_mm {
	struct list_head	sibling;
	char			desc[8];	/* string, include nul byte */
	int			fd;
	ref_t			refcount;

	unsigned long		mm_start;	/* mmap start at */
	unsigned long		mm_head;	/* first object */
	unsigned long		mm_cur;		/* next area could be used */
	unsigned long		mm_tail;	/* current mmap tail */
	unsigned long		mm_end;		/* mm_tail max */

	unsigned long		expandable : 1;
};

extern int clib_mm_setup(char *desc, int fd,
			 unsigned long start, size_t len, int expandable);
extern int clib_mm_cleanup(char *desc);
extern unsigned long clib_mm_get(char *desc, size_t len);

DECL_END

#endif /* end of include guard: CLIB_MM_H_PR1CMVVD */
