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

extern void mt_print_init_ncurse(void);
extern void mt_print_fini_ncurse(void);
extern void mt_print_add(void);
extern void mt_print_del(void);
extern void mt_print0(pthread_t id, char *buf);
extern void mt_print1(pthread_t id, const char *fmt, ...);

extern void mt_print_progress(double cur, double total);
extern void clib_pretty_fprint(FILE *s, int max, const char *fmt, ...);

DECL_END

#endif /* end of include guard: CLIB_PRINT_H_DQCESHGU */
