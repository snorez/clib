#ifndef logfile_H_ZGYJL6O9
#define logfile_H_ZGYJL6O9

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "./error.h"
#include "./string.h"
#include "./list.h"
#include "./file.h"

typedef regfile logfile;
typedef enum _logfile_level {debug, info, warn, error, fatal} logfile_level;

extern logfile *logfile_open(char *path);
extern int logfile_write(logfile *file, logfile_level level, char *fmt, ...);
extern int logfile_close(logfile *file);

#endif /* end of include guard: logfile_H_ZGYJL6O9 */
