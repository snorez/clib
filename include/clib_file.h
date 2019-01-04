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
#include "../include/clib_error.h"
#include "../include/clib_string.h"
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

struct file {
	struct stat stat;
	char *path;		/* file path or addr if has */
	list_comm rdata;
	list_comm wdata;

	int fd;
	int openflag;
};

typedef struct file regfile;

static inline buf_struct *regfile_get_rdata(regfile *file, list_comm *next_head)
{
	list_comm *head = &file->rdata, *next;
	if (list_comm_is_empty(head))
		return NULL;
	if (!next_head)
		return (buf_struct *)(((list_comm *)head->list_head.next)->data);
	if (next_head->list_head.next == (void *)head)
		return NULL;
	if (!list_comm_is_empty(next_head))
		head = next_head;
	next = (list_comm *)head->list_head.next;
	next_head->list_head = next->list_head;
	return (buf_struct *)next->data;
}

extern int path_exists(const char *path);
extern regfile *regfile_open(const char *path, int flag, ...);
extern int regfile_close(regfile *);
extern void set_file_max_size(size_t file_max_size);
extern size_t get_file_max_size(void);
extern int regfile_readall(regfile *);
extern int regfile_readlines(regfile *);
extern void set_io_speed(uint32_t val);
extern uint32_t get_io_speed(void);
extern int regfile_readline(regfile *, uint32_t lines);
extern int regfile_writelines(regfile *);
extern ssize_t regfile_read(regfile *file, void *buf, size_t count);
extern ssize_t regfile_write(regfile *file, void *buf, size_t count);
extern off_t regfile_lseek(regfile *file, off_t offs, int where);

DECL_END

#endif /* end of include guard: FILE_H_7JM8BHXT */
