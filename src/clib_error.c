/*
 * this file comes from `Advanced Unix programming`
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
#include "../include/clib.h"

static int dbg_mode;
/*
 * COLOR_B selections
 *	00(normal) 01(bold) 02(normal-light) 03(Italic) 04(underline) 07 09(mid-line)
 *	30-36 40-49
 * XXX: DO NOT use these functions in different threads
 */
#define	COLOR_B		"\033[07;31m"
#define COLOR_E		"\033[0m"
#define	COLOR_OFF	"\0"
static int color_p = 1;
static char *last_color_b = COLOR_B;
static char *last_color_e = COLOR_E;
static char *color_prompt_b = COLOR_B;
static char *color_prompt_e = COLOR_E;

static void err_common(int has_errno, int error, const char *fmt,
		       va_list ap)
{
	char buf[MAXLINE];
	memset(buf, 0, MAXLINE);
	memcpy(buf, color_prompt_b, strlen(color_prompt_b));
	vsnprintf(buf+strlen(buf), MAXLINE-strlen(buf), fmt, ap);
	if (has_errno)
		snprintf(buf+strlen(buf), MAXLINE-strlen(buf), ": %s",
			 strerror(errno));
	size_t len = strlen(buf);
	if (len >= MAXLINE-1-strlen(color_prompt_e)) {
		buf[MAXLINE-strlen(color_prompt_e)-5] = '.';
		buf[MAXLINE-strlen(color_prompt_e)-4] = '.';
		buf[MAXLINE-strlen(color_prompt_e)-3] = '.';
		memcpy(&buf[MAXLINE-strlen(color_prompt_e)-2], color_prompt_e,
				strlen(color_prompt_e));
		buf[MAXLINE-2] = '\n';
		buf[MAXLINE-1] = '\0';
	} else {
		memcpy(buf+len, color_prompt_e, strlen(color_prompt_e));
		buf[len+strlen(color_prompt_e)] = '\n';
	}
	fflush(stdout);
	fputs(buf, stderr);
	fflush(NULL);
}

void err_msg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_common(0, 0, fmt, ap);
	va_end(ap);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_common(1, errno, fmt, ap);
	va_end(ap);
}

void err_dbg(int has_errno, const char *fmt, ...)
{
	if (dbg_mode) {
		va_list ap;

		va_start(ap, fmt);
		if (has_errno)
			err_common(1, errno, fmt, ap);
		else
			err_common(0, 0, fmt, ap);
	}
}

void err_dbg1(int errval, const char *fmt, ...)
{
	if (dbg_mode) {
		va_list ap;

		va_start(ap, fmt);
		err_common(1, (errval < 0) ? -errval : errval, fmt, ap);
		va_end(ap);
	}
}

void err_dump(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_common(1, errno, fmt, ap);
	va_end(ap);

	abort();
	exit(1);
}

void err_exit(int flag_err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_common(flag_err, flag_err ? errno : 0, fmt, ap);
	va_end(ap);

	exit(0);
}

void set_dbg_mode(int val)
{
	dbg_mode = val;
}

int get_dbg_mode(void)
{
	return !!dbg_mode;
}

void err_color_on(void)
{
	color_p = 1;
	color_prompt_b = last_color_b;
	color_prompt_e = last_color_e;
}

void err_color_off(void)
{
	color_p = 0;
	color_prompt_b = COLOR_OFF;
	color_prompt_e = COLOR_OFF;
}

void err_set_color(char *b, char *e)
{
	last_color_b = b;
	last_color_e = e;
	err_color_on();
}
