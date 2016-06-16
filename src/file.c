/*
 * please compile with -D_FILE_OFFSET_BITS=64
 */
#include "../include/file.h"

int path_exists(const char *path)
{
	if (!path) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	struct stat tmp;
	int err = stat(path, &tmp);
	if (err == -1) {
		if (errno == ENOENT)
			return 0;
		err_dbg(1, err_fmt("stat err"));
		return -1;
	} else
		return 1;
}

reg_file *reg_file_open(const char *path, int flag, ...)
{
	if (!path) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
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
		err_dbg(1, err_fmt("open %s err"), path);
		return NULL;
	}

	int err;
	if ((flag & O_WRONLY) || (flag & O_RDWR)) {
		err = flock(fd, LOCK_EX | LOCK_NB);
		if (err == -1) {
			err_dbg(1, err_fmt("flock err"));
			goto close_ret;
		}
	} else if (flag & O_RDONLY) {
		err = flock(fd, LOCK_SH | LOCK_NB);
		if (err == -1) {
			err_dbg(1, err_fmt("flock err"));
			goto close_ret;
		}
	}

	reg_file *ret = malloc(sizeof(reg_file));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto close_ret;
	}
	memset(ret, 0, sizeof(reg_file));

	ret->path = path;
	ret->fd = fd;
	list_comm_init(&ret->pri_data);
	return ret;
close_ret:
	close(fd);
	return NULL;
}

int reg_file_close(reg_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = close(file->fd);
	if (!list_comm_is_empty(&file->pri_data))
		list_comm_str_struct_make_empty(&file->pri_data);
	free(file);
	return ret;
}

static uint64_t file_max_size = 1024*1024*1024;
void set_file_max_size(uint64_t val)
{
	file_max_size = val;
}

void get_file_max_size(uint64_t *val)
{
	if (!val) {
		err_msg(err_fmt("arg check err"));
		return;
	}

	*val = file_max_size;
}

int reg_file_readlines(reg_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	struct stat tmp_stat;
	int err = fstat(file->fd, &tmp_stat);
	if (err == -1) {
		err_dbg(1, err_fmt("fstat err"));
		return -1;
	}

	uint64_t len = (uint64_t)tmp_stat.st_size + 1;
	if ((len > file_max_size) || (len == 0)) {
		err_dbg(0, err_fmt("%s too large"), file->path);
		errno = EFBIG;
		return -1;
	}

	char *buf = malloc(len);
	if (!buf) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}
	memset(buf, 0, len);

	err = read(file->fd, buf, len);
	if (err == -1) {
		err_dbg(1, err_fmt("read err"));
		free(buf);
		return -1;
	}

	list_comm *data = (list_comm *)malloc(sizeof(list_comm) +
					      sizeof(line_struct));
	if (!data) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		lseek(file->fd, 0, SEEK_SET);
		free(buf);
		return -1;
	}
	memset(data, 0, sizeof(list_comm)+sizeof(line_struct));
	line_struct *tmp = (line_struct *)data->extra;
	tmp->str = buf;
	tmp->str_len = len-1;
	list_comm_append(&file->pri_data, data);
	return 0;
}

int reg_file_readline(reg_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!list_comm_is_empty(&file->pri_data))
		list_comm_str_struct_make_empty(&file->pri_data);

	int err;
	err = reg_file_readlines(file);
	if (err == -1) {
		err_dbg(1, err_fmt("reg_file_readlines err"));
		return -1;
	}

	list_comm *tmp = (list_comm *)file->pri_data.list_head.next;
	line_struct *tmp_data = (line_struct *)tmp->extra;
	err = str_split(&file->pri_data, tmp_data->str, "\n");
	if (err == -1) {
		free(tmp_data->str);
		free(tmp);
		list_comm_init(&file->pri_data);
		return -1;
	}
	free(tmp_data->str);
	free(tmp);
	return 0;
}

/* read *lines* lines to file->pri_data list, if the file lines less than
 * *lines*, then the whole file read into file->pri_data list
 * this func may read the file->fd multiple times, so
 * it needs to try tosave the orig seekpos in case of this func failed
 */
static uint32_t io_speed = 4096*1024*20;
void set_io_speed(uint32_t val)
{
	io_speed = val;
}

void get_io_speed(uint32_t *val)
{
	if (!val) {
		err_msg(err_fmt("arg check err"));
		return;
	}

	*val = io_speed;
}

/*
 * TODO: here, if LINE_BUF_SIZE is small, and the *lines* is too large
 * it will cause the new_alloc and make the process slow
 * so, if this happens, make LINE_BUF_SIZE bigger, here, we take it 80M
 * 80M means the speed of HDD(7200)
 * TODO: this function could not be used on binary file
 * XXX: return value
 * -1: err
 * >0: lines that have read
 */
int reg_file_readline_several(reg_file *file, uint32_t lines)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!list_comm_is_empty(&file->pri_data))
		list_comm_str_struct_make_empty(&file->pri_data);

	size_t buf_len = io_speed;
	char *buf = NULL;
	char *pos;
	int err, done = 0, last_read = 0;
	uint32_t cnt = 0;

	off_t orig_offs = lseek(file->fd, 0, SEEK_CUR);
	if (orig_offs == -1) {
		err_dbg(1, err_fmt("lseek error"));
		return -1;
	}

new_alloc:
	if (buf)
		free(buf);
	buf = malloc(buf_len);
	if (!buf) {
		errno = ENOMEM;
		err_dbg(1, err_fmt("realloc error"));
		return -1;
	}
	memset(buf, 0, buf_len);

	err = read(file->fd, buf, buf_len-1);
	if (err == -1) {
		err_dbg(1, err_fmt("read error"));
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
			errno = EFBIG;
			err = -1;
			err_dbg(0, err_fmt("try decrease the lines"));
			goto free_ret;
		}
		cnt = 0;
		err = lseek(file->fd, orig_offs, SEEK_SET);
		if (err == -1) {
			err_dbg(1, err_fmt("lseek error"));
			goto free_ret;
		}
		goto new_alloc;
	}

	if (done) {
		size_t more = strlen(pos) - 1;
		lseek(file->fd, 0-more, SEEK_CUR);
		memset(pos, 0, strlen(pos));
	}
	err = str_split(&file->pri_data, buf, "\n");
	if (err == -1) {
		err_dbg(1, err_fmt("str_split err"));
		err = -1;
		goto free_ret;
	}
	err = cnt;

free_ret:
	free(buf);
	return err;
}

/*
 * usage: before call this function, make sure the position of the file
 * is where you want it be
 */
int reg_file_writelines(reg_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	list_comm *tmp_node;
	int err;

	list_for_each_entry(tmp_node, &file->pri_data.list_head, list_head) {
		line_struct *tmp = (line_struct *)tmp_node->extra;
		err = write(file->fd, tmp->str, tmp->str_len);
		if (err == -1) {
			err_dbg(1, err_fmt("write error"));
			return -1;
		}

		err = write(file->fd, "\n", 1);
		if (err == -1) {
			err_dbg(1, err_fmt("write error"));
			return -1;
		}
	}
	return 0;
}
