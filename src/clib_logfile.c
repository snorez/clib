#include "../include/clib.h"

logfile *logfile_open(char *path)
{
	return regfile_open(path, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR);
}

int logfile_write(logfile *file, logfile_level level, char *fmt, ...)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	time_t cur_time = time(NULL);
	char buf[MAXLINE];
	char *msg = NULL;
	memset(buf, 0, MAXLINE);
	switch (level) {
	case clib_debug:
		msg = "DEBUG:";
		break;
	case clib_info:
		msg = "INFO: ";
		break;
	case clib_warn:
		msg = "WARN: ";
		break;
	case clib_error:
		msg = "ERROR:";
		break;
	case clib_fatal:
		msg = "FATAL:";
		break;
	default:
		break;
	}
	memcpy(buf, msg, strlen(msg));
	sprintf(buf+strlen(buf), "%s", asctime(localtime(&cur_time)));
	*(buf+strlen(buf)-1) = '\0';
	sprintf(buf+strlen(buf), ": ");

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), 4096-strlen(buf), fmt, ap);
	va_end(ap);
	*(buf+strlen(buf)) = '\n';
	return write(file->fd, buf, strlen(buf));
}

int logfile_close(logfile *file)
{
	return regfile_close(file);
}
