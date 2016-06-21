#ifndef LOG_H
#define LOG_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "./error.h"
#include "./string.h"
#include "./list.h"
#include "./file.h"

typedef text_file log_file;
typedef enum _log_level {debug, info, warn, error, fatal} log_level;

extern log_file *log_open(char *path);
extern int log_write(log_file *file, log_level level, char *fmt, ...);
extern int log_close(log_file *file);

#endif
