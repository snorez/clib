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

struct file {
	struct stat stat;
	char *path;		/* file path or addr if has */
	void *rdata;		/* file input buf, maybe a list_comm */
	void *wdata;		/* file output buf, maybe a list_comm */

	int fd;
	int openflag;
	pthread_mutex_t mutex;
};

typedef str_struct line_struct;
typedef struct file text;
typedef struct _text_ops {
	int	(*open)(text *file, void *path, int flag, ...);
	ssize_t (*read)(text *file, void *buf, size_t len, int flag);
	ssize_t (*write)(text *file, void *buf, size_t len, int flag);
	int	(*close)(text *file);
	off_t	(*lseek)(text *file, off_t offs, int where);
	//long	(*ioctl)(text *file, unsigned long request, ...);

	ssize_t (*readall)(text *file);
	ssize_t (*readlines)(text *file);
	ssize_t (*readline)(text *file);
	ssize_t (*writelines)(text *file);
} text_ops;

extern int path_exists(const char *path);
extern text *text_open(const char *path, int flag, ...);
extern int text_lock(text *file);
extern int text_trylock(text *file);
extern int text_unlock(text *file);
extern int text_close(text *);
extern void set_file_max_size(size_t file_max_size);
extern size_t get_file_max_size(void);
extern int text_readall(text *);
extern int text_readlines(text *);
extern void set_io_speed(uint32_t val);
extern uint32_t get_io_speed(void);
extern int text_readline(text *, uint32_t lines);
extern int text_writelines(text *);
extern ssize_t text_read(text *file, void *buf, size_t count);
extern ssize_t text_write(text *file, void *buf, size_t count);
extern off_t text_lseek(text *file, off_t offs, int where);

#endif
