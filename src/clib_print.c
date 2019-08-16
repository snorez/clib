/*
 * multi-thread pretty print
 *
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
#include "../include/clib_print.h"

static LIST_HEAD(print_head);
static lock_t print_head_lock;
static int use_std = 1;

void mt_print_init_ncurse(void)
{
	mutex_lock(&print_head_lock);
	if (!use_std)
		return;
	initscr();
	clear();
	refresh();
	use_std = 0;
	atexit(mt_print_fini_ncurse);
	mutex_unlock(&print_head_lock);
}

void mt_print_fini_ncurse(void)
{
	if (use_std)
		return;
	mutex_lock(&print_head_lock);
	endwin();
	use_std = 1;
	mutex_unlock(&print_head_lock);
}

/* this is called by thread */
void mt_print_add(void)
{
	mutex_lock(&print_head_lock);
	struct clib_print *t;
	list_for_each_entry(t, &print_head, sibling) {
		if (pthread_equal(t->threadid, pthread_self()))
			goto unlock;
	}
	t = malloc(sizeof(*t));
	if (!t) {
		err_dbg(0, "malloc err");
		goto unlock;
	}
	memset(t, 0, sizeof(*t));
	t->threadid = pthread_self();
	list_add_tail(&t->sibling, &print_head);

unlock:
	mutex_unlock(&print_head_lock);
	return;
}

void mt_print_del(void)
{
	mutex_lock(&print_head_lock);
	struct clib_print *t, *next;
	list_for_each_entry_safe(t, next, &print_head, sibling) {
		if (pthread_equal(t->threadid, pthread_self())) {
			list_del(&t->sibling);
			free(t);
			goto unlock;
		}
	}

unlock:
	mutex_unlock(&print_head_lock);
}

void mt_print0(pthread_t id, char *buf)
{
	int found = 0;

	mutex_lock(&print_head_lock);
	struct clib_print *t;

	if (!use_std) {
		clear();
		move(0, 0);
	}

	list_for_each_entry(t, &print_head, sibling) {
		if (pthread_equal(t->threadid, id)) {
			found = 1;
			int buflen = strlen(buf) + 1;
			if (buflen > CLIB_MT_PRINT_LINE_LEN)
				buflen = CLIB_MT_PRINT_LINE_LEN;
			memcpy(t->data, buf, buflen);

			if (use_std) {
				fprintf(stdout, "%s", t->data);
				fflush(stdout);
				break;
			}
		}
		if (!use_std) {
			addstr(t->data);
			refresh();
			int line, col;
			getyx(curscr, line, col);
			if (line >= (LINES-1)) {
				move(LINES-1, 0);
				for (int i = 0; i < col; i++)
					addch('.');
				refresh();
				break;
			}
			/* do not assume output contain a \n at last */
			if (col)
				move(line+1, 0);
		}
	}

	if ((!found) && use_std) {
		fprintf(stdout, "%s", buf);
		fflush(stdout);
	}

	mutex_unlock(&print_head_lock);
	return;
}

void mt_print1(pthread_t id, const char *fmt, ...)
{
	va_list ap;
	int found = 0;

	mutex_lock(&print_head_lock);
	struct clib_print *t;

	if (!use_std) {
		clear();
		move(0, 0);
	}

	list_for_each_entry(t, &print_head, sibling) {
		if (pthread_equal(t->threadid, id)) {
			found = 1;

			memset(t->data, 0, CLIB_MT_PRINT_LINE_LEN);
			va_start(ap, fmt);
			vsnprintf(t->data, CLIB_MT_PRINT_LINE_LEN-8, fmt, ap);
			va_end(ap);

			if (use_std) {
				fprintf(stdout, "%s", t->data);
				fflush(stdout);
				break;
			}
		}
		if (!use_std) {
			addstr(t->data);
			refresh();
			int line, col;
			getyx(curscr, line, col);
			if (line >= (LINES-1)) {
				move(LINES-1, 0);
				for (int i = 0; i < col; i++)
					addch('.');
				refresh();
				break;
			}
			/* do not assume output contain a \n at last */
			if (col)
				move(line+1, 0);
		}
	}

	if ((!found) && use_std) {
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
		fflush(stdout);
	}

	mutex_unlock(&print_head_lock);
	return;
}

static __thread int show_process_byte = 0;
void mt_print_progress(double cur, double total)
{
	if (show_process_byte)
		for (int i = 0; i < show_process_byte; i++)
			fprintf(stdout, "\b");
	show_process_byte = fprintf(stdout, "%.3f%%", cur * 100 / total);
	fflush(stdout);
	if (cur == total)
		show_process_byte = 0;
}

/* count \t as 8 bytes */
#define	TAB_BYTES	8
void clib_pretty_fprint(FILE *s, int max, const char *fmt, ...)
{
	max = clib_round_up(max, TAB_BYTES);
	char buf[max];
	memset(buf, 0, max);

	va_list ap;
	va_start(ap, fmt);

	int c = vsnprintf(buf, max, fmt, ap);
	int tabs = 0;
	if (c >= max) {
		buf[max-1] = '\0';
		buf[max-2] = '.';
		buf[max-3] = '.';
		buf[max-4] = '.';
		tabs = 1;
	} else {
		tabs = (max / 8) - (c / 8);
	}
	fprintf(s, "%s", buf);
	for (int i = 0; i < tabs; i++) {
		fprintf(s, "\t");
	}
	fflush(s);

	va_end(ap);
	return;
}
