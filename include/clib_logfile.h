#ifndef logfile_H_ZGYJL6O9
#define logfile_H_ZGYJL6O9

#include "../include/clib_utils.h"
#include "../include/clib_error.h"
#include "../include/clib_string.h"
#include "../include/clib_list.h"
#include "../include/clib_file.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

DECL_BEGIN

typedef regfile logfile;
typedef enum _logfile_level {
	clib_debug,
	clib_info,
	clib_warn,
	clib_error,
	clib_fatal
} logfile_level;

extern logfile *logfile_open(char *path);
extern int logfile_write(logfile *file, logfile_level level, char *fmt, ...);
extern int logfile_close(logfile *file);

DECL_END

#endif /* end of include guard: logfile_H_ZGYJL6O9 */
