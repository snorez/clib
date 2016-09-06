/*
 * please compile with -D_FILE_OFFSET_BITS=64
 */
#include "../include/class.h"
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
		errno = EAGAIN;
		return -1;
	} else
		return 1;
}

text *text_open(const char *path, int flag, ...)
{
	if (!path) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
	}

	int err;
	struct stat tmp_stat;
	memset(&tmp_stat, 0, sizeof(tmp_stat));
	if (!(flag & O_CREAT)) {
		err = stat(path, &tmp_stat);
		if (err == -1) {
			err_dbg(1, err_fmt("stat err"));
			return NULL;
		}
		if (!S_ISREG(tmp_stat.st_mode)) {
			err_dbg(0, err_fmt("%s filetype not right"), path);
			errno = EINVAL;
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
		err_dbg(1, err_fmt("open %s err"), path);
		return NULL;
	}

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

	text *ret = (text *)malloc_s(sizeof(text));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto close_ret;
	}

	ret->path = (char *)malloc_s(strlen(path)+1);
	if (!ret->path) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto free_ret;
	}

	ret->rdata = (char *)malloc_s(sizeof(list_comm));
	if (!ret->rdata) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto free2_ret;
	}
	list_comm_init(ret->rdata);

	ret->wdata = (char *)malloc_s(sizeof(list_comm));
	if (!ret->wdata) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto free3_ret;
	}
	list_comm_init(ret->wdata);

	memcpy(ret->path, path, strlen(path));
	ret->fd = fd;
	memcpy(&ret->stat, &tmp_stat, sizeof(tmp_stat));
	ret->openflag = flag;
	pthread_mutex_init(&ret->mutex, NULL);
	//ret->rwlock = PTHREAD_RWLOCK_INITIALIZER;
	return ret;
free3_ret:
	free_s((void **)&ret->rdata);
free2_ret:
	free_s((void **)&ret->path);
free_ret:
	free_s((void **)&ret);
close_ret:
	close(fd);
	return NULL;
}

int text_lock(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return pthread_mutex_lock(&file->mutex);
}

int text_trylock(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return pthread_mutex_trylock(&file->mutex);
}

int text_unlock(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return pthread_mutex_unlock(&file->mutex);
}

int text_close(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = close(file->fd);
	text_unlock(file);
	pthread_mutex_destroy(&file->mutex);
	if (file->path)
		free_s((void **)&file->path);
	if (file->rdata) {
		list_comm_str_struct_make_empty(file->rdata);
		free_s((void **)&file->rdata);
	}
	if (file->wdata) {
		list_comm_str_struct_make_empty(file->wdata);
		free_s((void **)&file->wdata);
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

int text_readall(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int err;

	size_t len = (size_t)file->stat.st_size + 1;
	if ((len > file_max_size) || (len == 0)) {
		err_dbg(0, err_fmt("%s too large"), file->path);
		errno = EFBIG;
		err = -1;
		goto unlock;
	}

	char *buf = (char *)malloc_s(len);
	if (!buf) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		err = -1;
		goto unlock;
	}

	err = read(file->fd, buf, len);
	if (err == -1) {
		err_dbg(1, err_fmt("read err"));
		goto free_ret;
	}

	list_comm *data = (list_comm *)malloc_s(sizeof(list_comm) +
						sizeof(line_struct));
	if (!data) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		lseek(file->fd, 0, SEEK_SET);
		err = -1;
		goto free_ret;
	}
	line_struct *tmp = (line_struct *)data->st;
	tmp->str = buf;
	tmp->str_len = len-1;
	list_comm_append(file->rdata, data);
	err = 0;
	goto unlock;
free_ret:
	free(buf);
unlock:
	return err;
}

int text_readlines(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!list_comm_is_empty(file->rdata)) {
		list_comm_str_struct_make_empty(file->rdata);
		list_comm_init(file->rdata);
	}

	int err;
	err = text_readall(file);
	if (err == -1) {
		err_dbg(1, err_fmt("text_readall err"));
		return -1;
	}

	list_comm *rhead = (list_comm *)file->rdata;
	list_comm *tmp = (list_comm *)rhead->list_head.next;
	line_struct *tmp_data = (line_struct *)tmp->st;
	err = str_split(file->rdata, tmp_data->str, "\n");
	if (err == -1)
		list_comm_init(file->rdata);
	free(tmp_data->str);
	free(tmp);
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
int text_readline(text *file, uint32_t lines)
{
	if (!file || !lines) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!list_comm_is_empty(file->rdata)) {
		list_comm_str_struct_make_empty(file->rdata);
		list_comm_init(file->rdata);
	}

	size_t buf_len = io_speed;
	char *buf = NULL;
	char *pos;
	int err, done = 0, last_read = 0;
	uint32_t cnt = 0;

	off_t orig_offs = lseek(file->fd, 0, SEEK_CUR);
	if (orig_offs == -1) {
		err_dbg(1, err_fmt("lseek err"));
		err = -1;
		goto unlock;
	}

new_alloc:
	if (buf)
		free_s((void **)&buf);
	buf = (char *)malloc_s(buf_len);
	if (!buf) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		err = -1;
		goto unlock;
	}

	err = read(file->fd, buf, buf_len-1);
	if (err == -1) {
		err_dbg(1, err_fmt("read err"));
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
			err_dbg(0, err_fmt("try decrease the lines"));
			errno = EFBIG;
			err = -1;
			goto free_ret;
		}
		cnt = 0;
		err = lseek(file->fd, orig_offs, SEEK_SET);
		if (err == -1) {
			err_dbg(1, err_fmt("lseek err"));
			goto free_ret;
		}
		goto new_alloc;
	}

	if (done) {
		size_t more = strlen(pos) - 1;
		err = lseek(file->fd, 0-more, SEEK_CUR);
		if (err == -1) {
			err_dbg(1, err_fmt("lseek err"));
			goto free_ret;
		}
		memset(pos, 0, strlen(pos));
	}
	err = str_split(file->rdata, buf, "\n");
	if (err == -1) {
		err_dbg(1, err_fmt("str_split err"));
		err = -1;
		goto free_ret;
	}
	err = cnt;

free_ret:
	free_s((void **)&buf);
unlock:
	return err;
}

/*
 * usage: before call this function, make sure the position of the file
 * is where you want it be
 */
int text_writelines(text *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	list_comm *tmp_node;
	list_comm *whead = (list_comm *)file->wdata;
	int err = 0;

	list_for_each_entry(tmp_node, &whead->list_head, list_head) {
		line_struct *tmp = (line_struct *)tmp_node->st;
		err = write(file->fd, tmp->str, tmp->str_len);
		if (err == -1) {
			err_dbg(1, err_fmt("write err"));
			goto unlock;
		}

		err = write(file->fd, "\n", 1);
		if (err == -1) {
			err_dbg(1, err_fmt("write err"));
			goto unlock;
		}
	}
unlock:
	return err;
}

ssize_t text_read(text *file, void *buf, size_t count)
{
	return read(file->fd, buf, count);
}

ssize_t text_write(text *file, void *buf, size_t count)
{
	return write(file->fd, buf, count);
}

off_t text_lseek(text *file, off_t offs, int where)
{
	return lseek(file->fd, offs, where);
}
