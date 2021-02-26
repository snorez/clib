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
#ifndef FILE_H_7JM8BHXT
#define FILE_H_7JM8BHXT

#include "../include/clib_utils.h"
#include "../include/clib_eh.h"
#include "../include/clib_buf.h"
#include "../include/clib_list.h"
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
#include <dirent.h>
#include <linux/limits.h>

DECL_BEGIN

/* for reg file */
enum regfile_types {
	REGFILE_T_TXT,
	REGFILE_T_BIN,
};

typedef struct {
	struct stat		stat;
	char			*path;		/* file path or addr if has */
	int			fd;
	int			openflag;
	int			type;
	int			fake;

	union {
		struct {
			struct list_head	rdata;
			struct list_head	wdata;
		} txtdata;
		struct {
			char			*rbuf;
			char			*wbuf;
		} bindata;
	} data;
} regfile;
#define	txt_rdata(file) (&(((regfile *)file)->data.txtdata.rdata))
#define	txt_wdata(file)	(&(((regfile *)file)->data.txtdata.wdata))
#define	bin_rdata(file)	(((regfile *)file)->data.bindata.rbuf)
#define	bin_wdata(file)	(((regfile *)file)->data.bindata.wbuf)

extern int abs_path(const char *path);
extern int path_exists(const char *path);
extern int clib_open(const char *pathname, int flags, ...);
extern ssize_t clib_read(int fd, void *buf, size_t count);
extern ssize_t clib_write(int fd, void *buf, size_t count);
extern char *clib_loadfile(const char *path, size_t *len);

extern regfile *regfile_open(int type, const char *path, int flag, ...);
extern regfile *regfile_open_fake(int type);
extern int regfile_close(regfile *);
extern int regfile_readall(regfile *);

extern void set_file_max_size(size_t file_max_size);
extern size_t get_file_max_size(void);
extern void set_io_speed(uint32_t val);
extern uint32_t get_io_speed(void);

extern int txtfile_readlines(regfile *);
extern int txtfile_readline(regfile *, uint32_t lines);
extern int txtfile_writelines(regfile *);
extern int clib_split_file(char *path, char *bkp, unsigned long start,
			   unsigned long end, int verbose);
extern int clib_copy_file_bytes(char *path, char *bkp, unsigned long bytes,
				int verbose);
extern int clib_copy_file(char *src, char *dest, int verbose);

DECL_END

#endif /* end of include guard: FILE_H_7JM8BHXT */
