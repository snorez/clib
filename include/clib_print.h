#ifndef CLIB_PRINT_H_DQCESHGU
#define CLIB_PRINT_H_DQCESHGU

#include "../include/clib.h"
#include <ncurses.h>

DECL_BEGIN

#define	CLIB_MT_PRINT_LINE_LEN	256
struct clib_print {
	struct list_head	sibling;
	pthread_t		threadid;
	char			data[CLIB_MT_PRINT_LINE_LEN];
};

extern void mt_print_init(void);
extern void mt_print_add(void);
extern void mt_print_del(void);
extern void mt_print(pthread_t id, const char *fmt, ...);
extern void mt_print_fini(void);
extern void mt_print_progress(double cur, double total);

DECL_END

#endif /* end of include guard: CLIB_PRINT_H_DQCESHGU */
