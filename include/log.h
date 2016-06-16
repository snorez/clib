#ifndef LOG_H
#define LOG_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "./error.h"
#include "string.h"
#include "list.h"

typedef struct _log_file {
	int fd;
	const char *path;
} log_file;

extern log_file *log_open(char *path);
extern int log_write(log_file *file, char *fmt, ...);
extern int log_close(log_file *file);

#endif
