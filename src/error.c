/*
 * this file comes from `Advanced Unix programming`
 */
#include "../include/error.h"

static int dbg_mode;

static void err_common(int has_errno, int error, const char *fmt,
		       va_list ap)
{
	char buf[MAXLINE];
	vsnprintf(buf, MAXLINE, fmt, ap);
	if (has_errno)
		snprintf(buf+strlen(buf), MAXLINE-strlen(buf), ": %s",
			 strerror(errno));
	strncat(buf, "\n", MAXLINE);
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

int err_ret(int has_errno, int retval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_dbg(has_errno, fmt, ap);
	va_end(ap);

	return retval;
}

void set_dbg_mode(int val)
{
	dbg_mode = val;
}
