/*
 * please compile with -D_FILE_OFFSET_BITS=64
 * TODO, multithread support
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
#include "../include/clib.h"

int path_exists(const char *path)
{
	if (!path) {
		err_dbg(0, "arg check err");
		return -1;
	}

	struct stat tmp;
	int err = stat(path, &tmp);
	if (err == -1) {
		if (errno == ENOENT)
			return 0;
		err_dbg(1, "stat err");
		return -1;
	} else
		return 1;
}

#define	IO_BYTES	(512*1024*1024)
int clib_open(const char *pathname, int flags, ...)
{
	int fd;
	flags |= O_DSYNC;

	if (flags & O_CREAT) {
		mode_t mode;
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		fd = open(pathname, flags, mode);
	} else
		fd = open(pathname, flags);

	return fd;
}

ssize_t clib_read(int fd, void *buf, size_t count)
{
	size_t read_bytes = 0;
	size_t bytes_to_read = IO_BYTES;
	int err;
	while (1) {
		if (read_bytes >= count)
			break;

		bytes_to_read = count - read_bytes;
		if (bytes_to_read > IO_BYTES)
			bytes_to_read = IO_BYTES;
		err = read(fd, buf+read_bytes, bytes_to_read);
		if (err != bytes_to_read) {
			err_dbg(1, "read err");
			return -1;
		}

		read_bytes += bytes_to_read;
	}

	return count;
}

ssize_t clib_write(int fd, void *buf, size_t count)
{
	size_t write_bytes = 0;
	size_t bytes_to_write = IO_BYTES;
	int err;

	while (1) {
		if (write_bytes >= count)
			break;

		bytes_to_write = count - write_bytes;
		if (bytes_to_write > IO_BYTES)
			bytes_to_write = IO_BYTES;

		err = write(fd, buf+write_bytes, bytes_to_write);
		if (err != bytes_to_write) {
			err_dbg(1, "write err");
			return -1;
		}

		write_bytes += bytes_to_write;
	}

	return count;
}

char *clib_loadfile(const char *path)
{
	int fd = -1, err = 0;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		err_dbg(1, "open err");
		return NULL;
	}

	err = fstat(fd, &st);
	if (err == -1) {
		err_dbg(1, "fstat err");
		goto close_out;
	}

	char *b = malloc(st.st_size+1);
	if (!b) {
		err_dbg(0, "malloc err");
		goto close_out;
	}
	memset(b, 0, st.st_size+1);

	err = read(fd, b, st.st_size);
	if (err != st.st_size) {
		err_dbg(0, "read not complete");
		goto free_out;
	}

	close(fd);
	return b;

free_out:
	free(b);
close_out:
	close(fd);
	return NULL;
}

regfile *regfile_open(int type, const char *path, int flag, ...)
{
	if (!path) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	int err;
	struct stat tmp_stat;
	memset(&tmp_stat, 0, sizeof(tmp_stat));
	if (!(flag & O_CREAT)) {
		err = stat(path, &tmp_stat);
		if (err == -1) {
			err_dbg(1, "stat err");
			return NULL;
		}
		if (!S_ISREG(tmp_stat.st_mode)) {
			err_dbg(0, "%s filetype not right", path);
			return NULL;
		}
	}

	int fd;
	if (flag & O_CREAT) {
		mode_t mode;
		va_list ap;
		va_start(ap, flag);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		fd = open(path, flag, mode);
	} else
		fd = open(path, flag);

	if (fd == -1) {
		err_dbg(1, "open %s err", path);
		return NULL;
	}

	if ((flag & O_WRONLY) || (flag & O_RDWR)) {
		err = flock(fd, LOCK_EX | LOCK_NB);
		if (err == -1) {
			err_dbg(1, "flock err");
			goto close_ret;
		}
	} else if (flag & O_RDONLY) {
		err = flock(fd, LOCK_SH | LOCK_NB);
		if (err == -1) {
			err_dbg(1, "flock err");
			goto close_ret;
		}
	}

	regfile *ret = (regfile *)malloc(sizeof(regfile));
	if (!ret) {
		err_dbg(0, "malloc err");
		goto close_ret;
	}

	ret->path = (char *)malloc(strlen(path)+1);
	if (!ret->path) {
		err_dbg(0, "malloc err");
		goto free_ret;
	}
	memcpy(ret->path, path, strlen(path)+1);

	ret->fd = fd;
	memcpy(&ret->stat, &tmp_stat, sizeof(tmp_stat));
	ret->openflag = flag;
	ret->type = type;

	if (type == REGFILE_T_TXT) {
		INIT_LIST_HEAD(txt_rdata(ret));
		INIT_LIST_HEAD(txt_wdata(ret));
	} else if (type == REGFILE_T_BIN) {
		;
	} else {
		err_dbg(0, "type not implemented");
		goto free_ret1;
	}
	return ret;

free_ret1:
	free(ret->path);
free_ret:
	free(ret);
close_ret:
	close(fd);
	return NULL;
}

int regfile_close(regfile *file)
{
	if (!file) {
		err_dbg(0, "arg check err");
		return -1;
	}

	int ret = close(file->fd);
	if (file->path)
		free(file->path);
	if (file->type == REGFILE_T_TXT) {
		if (!list_empty(txt_rdata(file)))
			buf_struct_list_cleanup(txt_rdata(file));
		if (!list_empty(txt_wdata(file)))
			buf_struct_list_cleanup(txt_wdata(file));
	} else if (file->type == REGFILE_T_BIN) {
		if (bin_rdata(file))
			free(bin_rdata(file));
		if (bin_wdata(file))
			free(bin_wdata(file));
	} else {
		err_dbg(0, "BUG: this should not happen");
	}

	free(file);
	return ret;
}

static volatile size_t file_max_size = 1024*1024*1024;
void set_file_max_size(size_t val)
{
	file_max_size = val;
}

size_t get_file_max_size(void)
{
	return file_max_size;
}

int regfile_readall(regfile *file)
{
	if (!file) {
		err_dbg(0, "arg check err");
		return -1;
	}

	int err;

	size_t len = (size_t)file->stat.st_size + 1;
	if ((len > file_max_size) || (len == 0)) {
		err_dbg(0, "%s too large", file->path);
		err = -1;
		goto unlock;
	}

	char *buf = (char *)malloc(len);
	if (!buf) {
		err_dbg(0, "malloc err");
		err = -1;
		goto unlock;
	}

	err = read(file->fd, buf, len);
	if (err == -1) {
		err_dbg(1, "read err");
		goto free_ret;
	}

	if (file->type == REGFILE_T_TXT) {
		err = buf_struct_new_append(txt_rdata(file), buf, len);
		if (err) {
			err_dbg(0, "buf_struct_new_append err");
			lseek(file->fd, 0, SEEK_SET);
			err = -1;
			goto free_ret;
		}
	} else if (file->type == REGFILE_T_BIN) {
		bin_rdata(file) = buf;
		buf = NULL;
	} else {
		err_dbg(0, "BUG: this should not happen");
	}

free_ret:
	free(buf);
unlock:
	return err;
}

int txtfile_readlines(regfile *file)
{
	if (!file || (file->type != REGFILE_T_TXT)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	if (!list_empty(txt_rdata(file))) {
		buf_struct_list_cleanup(txt_rdata(file));
		INIT_LIST_HEAD(txt_rdata(file));
	}

	int err;
	err = regfile_readall(file);
	if (err == -1) {
		err_dbg(1, "regfile_readall err");
		return -1;
	}

	list_comm *cur, *next;
	list_for_each_entry_safe(cur, next, txt_rdata(file), list_head) {
		buf_struct *bs = (void *)cur->data;
		list_del(&cur->list_head);
		if (!list_empty(txt_rdata(file))) {
			err_dbg(0, "rdata should be empty now");
			err = -1;
			goto err_out;
		}

		err = str_split(txt_rdata(file), bs->buf, "\n");
		free(bs->buf);
		free(cur);
		break;
	}

err_out:
	if (err == -1)
		INIT_LIST_HEAD(txt_rdata(file));
	return err;
}

static volatile uint32_t io_speed = 4096*1024*20;
void set_io_speed(uint32_t val)
{
	io_speed = val;
}

uint32_t get_io_speed(void)
{
	return io_speed;
}

/* read *lines* lines to file->pri_data list, if the file lines less than
 * *lines*, then the whole file read into file->pri_data list
 * this func may read the file->fd multiple times, so
 * it needs to try tosave the orig seekpos in case of this func failed
 */
/*
 * TODO: here, if LINE_BUF_SIZE is small, and the *lines* is too large
 * it will cause the new_alloc and make the process slow
 * so, if this happens, make LINE_BUF_SIZE bigger, here, we take it 80M
 * 80M means the speed of HDD(7200) on my laptop
 * TODO: this function could not be used on binary file
 * XXX: return value
 * -1: err
 * >0: lines that have read
 */
int txtfile_readline(regfile *file, uint32_t lines)
{
	if (!file || (file->type != REGFILE_T_TXT) || !lines) {
		err_dbg(0, "arg check err");
		return -1;
	}

	if (!list_empty(txt_rdata(file))) {
		buf_struct_list_cleanup(txt_rdata(file));
		INIT_LIST_HEAD(txt_rdata(file));
	}

	size_t buf_len = io_speed;
	char *buf = NULL;
	char *pos;
	int err, done = 0, last_read = 0;
	uint32_t cnt = 0;

	off_t orig_offs = lseek(file->fd, 0, SEEK_CUR);
	if (orig_offs == -1) {
		err_dbg(1, "lseek err");
		err = -1;
		goto unlock;
	}

new_alloc:
	if (buf)
		free(buf);
	buf = (char *)malloc(buf_len);
	if (!buf) {
		err_dbg(0, "malloc err");
		err = -1;
		goto unlock;
	}

	err = read(file->fd, buf, buf_len-1);
	if (err == -1) {
		err_dbg(1, "read err");
		goto free_ret;
	} else if (err < (buf_len - 1))
		last_read = 1;

	pos = buf;
	while ((pos = strstr(pos, "\n"))) {
		cnt++;
		if (cnt >= lines) {
			done = 1;
			break;
		}
		pos++;
	}

	if ((!done) && (!last_read)) {
		buf_len += io_speed;
		if (buf_len >= (file_max_size)) {
			err_dbg(0, "try decrease the lines");
			err = -1;
			goto free_ret;
		}
		cnt = 0;
		err = lseek(file->fd, orig_offs, SEEK_SET);
		if (err == -1) {
			err_dbg(1, "lseek err");
			goto free_ret;
		}
		goto new_alloc;
	}

	if (done) {
		size_t more = strlen(pos) - 1;
		err = lseek(file->fd, 0-more, SEEK_CUR);
		if (err == -1) {
			err_dbg(1, "lseek err");
			goto free_ret;
		}
		memset(pos, 0, strlen(pos));
	}
	err = str_split(txt_rdata(file), buf, "\n");
	if (err == -1) {
		err_dbg(1, "str_split err");
		err = -1;
		goto free_ret;
	}
	err = cnt;

free_ret:
	free(buf);
unlock:
	return err;
}

/*
 * usage: before call this function, make sure the position of the file
 * is where you want it be
 */
int txtfile_writelines(regfile *file)
{
	if (!file || (file->type != REGFILE_T_TXT)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	list_comm *tmp_node;
	int err = 0;

	list_for_each_entry(tmp_node, txt_wdata(file), list_head) {
		buf_struct *tmp = (buf_struct *)tmp_node->data;
		err = write(file->fd, tmp->buf, tmp->buf_len-1);
		if (err == -1) {
			err_dbg(1, "write err");
			goto unlock;
		}

		err = write(file->fd, "\n", 1);
		if (err == -1) {
			err_dbg(1, "write err");
			goto unlock;
		}
	}
unlock:
	return err;
}

#define	COPY_BLKSZ	(256*1024*1024)
static char buf[COPY_BLKSZ];
int clib_copy_file(char *path, char *bkp, unsigned long bytes)
{
	char *infile = path;
	char *outfile = bkp;

	int fd0 = open(infile, O_RDONLY);
	if (fd0 == -1) {
		err_dbg(1, "open err");
		return -1;
	}

	int fd1 = open(outfile, O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC,
			S_IRUSR | S_IWUSR);
	if (fd1 == -1) {
		err_dbg(1, "open err");
		close(fd0);
		return -1;
	}

	struct stat st;
	int err = fstat(fd0, &st);
	if (err == -1) {
		err_dbg(1, "fstat err");
		close(fd0);
		close(fd1);
		return -1;
	}

	unsigned long total_bytes = st.st_size;
	if (!bytes)
		bytes = total_bytes;
	fprintf(stdout, "%s: prepare copy %ld bytes of %ld\n",
			__FUNCTION__, bytes, total_bytes);
	fflush(stdout);

	unsigned long left = bytes;
	while (1) {
		fprintf(stdout, "\r%s: process %.3f%%", __FUNCTION__,
				(double)(bytes-left) * 100 / bytes);
		fflush(stdout);

		if (!left)
			break;
		unsigned long this_copy = left;
		if (this_copy > COPY_BLKSZ)
			this_copy = COPY_BLKSZ;
		memset(buf, 0, this_copy);
		err = read(fd0, buf, this_copy);
		if (err != this_copy) {
			err_dbg(1, "read err");
			close(fd0);
			close(fd1);
			return -1;
		}

		err = write(fd1, buf, this_copy);
		if (err != this_copy) {
			err_dbg(1, "write err");
			close(fd0);
			close(fd1);
			return -1;
		}

		left -= this_copy;
	}
	fprintf(stdout, "\n");
	fflush(stdout);

	return 0;
}
