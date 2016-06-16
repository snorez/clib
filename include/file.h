#ifndef __FILE_H__
#define __FILE_H__

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/file.h>
#include <linux/limits.h>
#include "./error.h"
#include "./string.h"
#include "./list.h"

/* XXX: reg_file use list_dt, so should not be used any more */
typedef str_struct line_struct;
typedef struct _reg_file {
	list_comm pri_data;
	const char *path;
	int fd;
} reg_file;

extern int path_exists(const char *path);
extern reg_file *reg_file_open(const char *path, int flag, ...);
extern int reg_file_close(reg_file *);
extern void set_file_max_size(uint64_t file_max_size);
extern int reg_file_readlines(reg_file *);
extern int reg_file_readline(reg_file *);
extern void set_line_buf_size(uint32_t line_buf_size);
extern int reg_file_readline_several(reg_file *, uint32_t lines);
extern int reg_file_writelines(reg_file *);

#endif
