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
#include "../include/clib.h"

uint32_t min_32(uint32_t a, uint32_t b)
{
	return (a > b) ? b : a;
}

uint64_t min_64(uint64_t a, uint64_t b)
{
	return (a > b) ? b : a;
}

uint32_t max_32(uint32_t a, uint32_t b)
{
	return (a > b) ? a : b;
}

uint64_t max_64(uint64_t a, uint64_t b)
{
	return (a > b) ? a : b;
}

void *malloc_s(size_t size)
{
	char *ret = (char *)malloc(size);
	if (ret)
		memset(ret, 0, size);
	return (void *)ret;
}

void free_s(void **addr)
{
	if (!addr || !(*addr))
		return;
	free(*addr);
	*addr = NULL;
}

int hex2int(char *hex)
{
	int ret = 0;
	for (int i = 7; i >= 0; i--) {
		char c = hex[i];
		if ((c >= '0') && (c <= '9'))
			ret += (c-'0')*(1<<(4*(7-i)));
		else if ((c >= 'A') && (c <= 'Z'))
			ret += ((c-'A')+10)*(1<<(4*(7-i)));
		else if ((c >= 'a') && (c <= 'z'))
			ret += ((c-'a')+10)*(1<<(4*(7-i)));
	}
	return ret;
}

/*
 * close aslr and execute this program again
 */
int no_aslr(int argc, char *argv[])
{
	int err = 0;
	int fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 3) {
		err_dbg(0, err_fmt("something goes wrong"));
		return -1;
	}

	struct stat f_prev, f_cur;
	err = fstat(fd-1, &f_prev);
	if (err == -1) {
		err_dbg(1, err_fmt("fstat err"));
		close(fd);
		return -1;
	}
	err = fstat(fd, &f_cur);
	if (err == -1) {
		err_dbg(1, err_fmt("fstat err"));
		close(fd);
		return -1;
	}

	if (memcmp(&f_prev, &f_cur, sizeof(f_prev))) {
		err = personality(ADDR_NO_RANDOMIZE);
		if (err == -1) {
			err_dbg(1, err_fmt("personality err"));
			return -1;
		}
		extern char **environ;
		execve(argv[0], argv, environ);
		return 0;
	} else {
		close(fd);
		close(fd-1);
		return 0;
	}
}

static int tmp_std_fd = -1;
static const char *tmp_std_file = "/tmp/tmp_std_file";
int tmp_close_std(int close_fd)
{
	int err = 0;
	tmp_std_fd = dup(close_fd);
	if (tmp_std_fd == -1) {
		err_dbg(1, err_fmt("dup err"));
		return -1;
	}

	int fd = open(tmp_std_file, O_RDWR | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR);
	if (fd == -1) {
		err_dbg(1, err_fmt("open err"));
		close(tmp_std_fd);
		return -1;
	}

	err = dup2(fd, close_fd);
	if (err != close_fd) {
		err_dbg(1, err_fmt("dup2 err"));
		close(fd);
		close(tmp_std_fd);
		return -1;
	}
	close(fd);
	return 0;
}

int restore_std(int closed_fd)
{
	fflush(stdout);
	fflush(stderr);
	int err = dup2(tmp_std_fd, closed_fd);
	if (err != closed_fd) {
		err_dbg(1, err_fmt("dup2 err, %d"), err);
		return -1;
	}

	close(tmp_std_fd);
	tmp_std_fd = -1;
	return 0;
}

int output_tmp_std(void)
{
	char cmd[64];
	memset(cmd, 0, 64);
	snprintf(cmd, 64, "cat %s", tmp_std_file);
	int err = system(cmd);
	if (err) {
		err_dbg(1, err_fmt("run %s err"), cmd);
		return -1;
	}
	return 0;
}

long get_memory_avail(void)
{
	int fd = open("/proc/meminfo", O_RDONLY);
	if (fd == -1) {
		err_dbg(1, err_fmt("open err"));
		return -1;
	}

	char buf[4096];
	memset(buf, 0, 4096);
	int err = read(fd, buf, 4096);
	if (err == -1) {
		err_dbg(1, err_fmt("read err"));
		close(fd);
		return -1;
	}
	close(fd);

	char *string = "MemAvailable:";
	char *p = strstr(buf, string);
	if (!p) {
		err_dbg(0, err_fmt("MemAvailable not found"));
		return -1;
	}

	p += strlen(string);
	while (isspace(*p))
		p++;

	return (unsigned long)1024 * atoll(p);
}

static __thread struct timeval tv0, tv1;
void time_acct_start(void)
{
	int err = gettimeofday(&tv0, NULL);
	if (err == -1) {
		err_dbg(1, err_fmt("gettimeofday err"));
		memset(&tv0, 0, sizeof(tv0));
		return;
	}
}

void time_acct_end(void)
{
	if (!tv0.tv_sec)
		return;

	int err = gettimeofday(&tv1, NULL);
	if (err == -1) {
		err_dbg(1, err_fmt("gettimeofday err"));
		memset(&tv0, 0, sizeof(tv0));
		return;
	}

	if (tv1.tv_usec < tv0.tv_usec) {
		fprintf(stdout, "process take %ld seconds, %ld microsec\n",
				tv1.tv_sec-1-tv0.tv_sec,
				tv1.tv_usec+1000000-tv0.tv_usec);
	} else {
		fprintf(stdout, "process take %ld seconds, %ld microsec\n",
				tv1.tv_sec - tv0.tv_sec,
				tv1.tv_usec-tv0.tv_usec);
	}
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
			err_dbg(1, err_fmt("read err"));
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
			err_dbg(1, err_fmt("write err"));
			return -1;
		}

		write_bytes += bytes_to_write;
	}

	return count;
}

char *clib_ap_start(const char *fmt, ...)
{
	int size = 0;
	char *p = NULL;
	va_list ap;

	va_start(ap, fmt);
	size = vsnprintf(p, size, fmt, ap);
	va_end(ap);

	if (size < 0)
		return NULL;

	size++;
	p = malloc(size);
	if (p == NULL)
		return NULL;

	va_start(ap, fmt);
	size = vsprintf(p, fmt, ap);
	if (size < 0) {
		free(p);
		return NULL;
	}
	va_end(ap);

	return p;
}

void clib_ap_end(char *p)
{
	free(p);
}
