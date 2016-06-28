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
#include <dirent.h>
#include <linux/limits.h>
#include <pthread.h>
#include "./error.h"
#include "./string.h"
#include "./list.h"
#include "./utils.h"

struct file;
typedef struct _base_io {
	int	(*open)(struct file *file, void *path, int flag, ...);
	ssize_t	(*in)(struct file *file, void *buf, size_t len, int flag);
	ssize_t	(*out)(struct file *file, void *buf, size_t len, int flag);
	int	(*close)(struct file *file);
	loff_t	(*llseek)(struct file *file, loff_t offs, int where);
	long	(*ioctl)(struct file *file, unsigned long request, ...);
} base_io;

struct file_ops {
	base_io bio;
};

struct file {
	struct stat stat;
	char *path;		/* file path or addr if has */
	void *rdata;		/* file input buf, maybe a list_comm */
	void *wdata;		/* file output buf, maybe a list_comm */

	int fd;
	int openflag;
	pthread_rwlock_t rwlock;
};

typedef str_struct line_struct;
typedef struct _text {
	struct file file;
	struct file_ops *ops;
} text;

extern int path_exists(const char *path);
extern text *text_open(const char *path, int flag, ...);
extern int text_close(text *);
extern void set_file_max_size(size_t file_max_size);
extern size_t get_file_max_size(void);
extern int text_readall(text *);
extern int text_readlines(text *);
extern void set_io_speed(uint32_t val);
extern uint32_t get_io_speed(void);
extern int text_readline(text *, uint32_t lines);
extern int text_writelines(text *);

#endif
