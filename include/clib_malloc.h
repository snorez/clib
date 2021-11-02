/*
 * TODO
 * Copyright (C) 2021  zerons
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
#ifndef CLIB_MALLOC_H_MCIZYOJP
#define CLIB_MALLOC_H_MCIZYOJP

#include "../include/clib.h"

#ifndef xmalloc
#define	xmalloc malloc
#endif

#ifndef xrealloc
#define	xrealloc realloc
#endif

#define	CLIB_HEAP_MSG	"CLIB_HEAP"
#define	CLIB_MALLOC(sz, slow) \
({\
	void *____v = clib_malloc(sz, (char *)__FILE__, __LINE__, slow);\
	____v;\
 })

#define	CLIB_FREE(ptr, slow) \
({\
	clib_free(ptr, (char *)__FILE__, __LINE__, slow);\
 })

#define	CLIB_REALLOC(ptr, sz, slow) \
({\
	void *____v = clib_realloc(ptr, sz, (char *)__FILE__, __LINE__, slow);\
	____v;\
 })

DECL_BEGIN

static inline void *clib_malloc(size_t size, char *file, int line, int slow)
{
	void *ret = xmalloc(size);
	if (unlikely(slow))
		fprintf(stderr, "%s + %p, %s %d\n", CLIB_HEAP_MSG,
			ret, file, line);
	return ret;
}

static inline void clib_free(void *ptr, char *file, int line, int slow)
{
	if (unlikely(slow))
		fprintf(stderr, "%s - %p, %s %d\n", CLIB_HEAP_MSG,
			ptr, file, line);
	free(ptr);
}

static inline void *clib_realloc(void *ptr, size_t size, char *file, int line,
				 int slow)
{
	void *ret = xrealloc(ptr, size);
	if (unlikely(slow)) {
		fprintf(stderr, "%s - %p, %s %d\n", CLIB_HEAP_MSG,
			ptr, file, line);
		fprintf(stderr, "%s + %p, %s %d\n", CLIB_HEAP_MSG,
			ret, file, line);
	}
	return ret;
}

C_SYM int clib_inner_slow_heap;
#define	CLIB_INNER_MALLOC(sz)		CLIB_MALLOC(sz, clib_inner_slow_heap)
#define	CLIB_INNER_FREE(ptr)		CLIB_FREE(ptr, clib_inner_slow_heap)
#define	CLIB_INNER_REALLOC(ptr, sz)	CLIB_REALLOC(ptr, sz, clib_inner_slow_heap)

static inline void clib_slow_heap(void)
{
	clib_inner_slow_heap = 1;
}

static inline void clib_fast_heap(void)
{
	clib_inner_slow_heap = 0;
}

#if 0
struct clib_heap_audit_node {
	struct slist_head	sibling;
	void			*ptr;
	size_t			alloc_len;
};

C_SYM void clib_heap_audit_enable(void);
C_SYM void clib_heap_audit_disable(void);
C_SYM void *clib_heap_audit_alloc(size_t len);
C_SYM void *clib_heap_audit_realloc(void *ptr, size_t len);
C_SYM void clib_heap_audit_free(void *ptr);
C_SYM void *clib_heap_audit(void *ptr, ssize_t offset, size_t rlen, char *file, int line);
#define	CLIB_HEAP_AUDIT_ALLOC(sz) \
({\
	void *____v = clib_heap_audit_alloc(sz);\
	____v;\
 })

#define	CLIB_HEAP_AUDIT_REALLOC(ptr, sz) \
({\
	void *____v = clib_heap_audit_realloc(ptr, sz);\
	____v;\
 })

#define	CLIB_HEAP_AUDIT(ptr, offset, rlen) \
({\
	void *____v = clib_heap_audit(ptr, offset, rlen, (char *)__FILE__, __LINE__);\
	____v;\
 })

#define	CLIB_HEAP_AUDIT_FREE(ptr) \
({\
	clib_heap_audit_free(ptr);\
 })
#endif

DECL_END

#endif /* end of include guard: CLIB_MALLOC_H_MCIZYOJP */
