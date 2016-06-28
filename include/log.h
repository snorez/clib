#ifndef LOG_H
#define LOG_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "./error.h"
#include "./string.h"
#include "./list.h"
#include "./file.h"

typedef text log;
typedef enum _log_level {debug, info, warn, error, fatal} log_level;

extern log *log_open(char *path);
extern int log_write(log *file, log_level level, char *fmt, ...);
extern int log_close(log *file);

#endif
