#include "../include/log.h"

log_file *log_open(char *path)
{
	if (!path) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
	}

	int fd;
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		err_dbg(1, err_fmt("open %s err"), path);
		return NULL;
	}

	log_file *ret = (log_file *)malloc(sizeof(log_file));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		close(fd);
		return NULL;
	}

	ret->fd = fd;
	ret->path = path;
	return ret;
}

int log_write(log_file *file, char *fmt, ...)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	time_t cur_time = time(NULL);
	char buf[4096];
	memset(buf, 0, 4096);
	sprintf(buf, "%s", asctime(localtime(&cur_time)));
	*(buf+strlen(buf)-1) = '\0';
	sprintf(buf+strlen(buf), ": ");

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), 4096-strlen(buf), fmt, ap);
	va_end(ap);
	*(buf+strlen(buf)) = '\n';
	return write(file->fd, buf, strlen(buf));
}

int log_close(log_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = close(file->fd);
	free(file);
	return ret;
}
