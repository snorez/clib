#ifndef CLIB_MM_H_PR1CMVVD
#define CLIB_MM_H_PR1CMVVD

/*
 * this is for using continuous memory area. without any free action
 * there are two kind of memory: not-expanded, expandable
 */
#include "../include/clib.h"
#include <sys/mman.h>

DECL_BEGIN

#define	CLIB_MM_DESC_LEN	8
#define	CLIB_MM_MMAP_BLKSZ	(64*1024*1024)
struct clib_mm {
	struct list_head	sibling;
	char			desc[8];	/* string, include nul byte */
	int			fd;

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
