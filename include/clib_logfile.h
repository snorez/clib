/*
 * TODO
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
