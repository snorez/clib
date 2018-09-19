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
	if (fd == 3) {
		err = personality(ADDR_NO_RANDOMIZE);
		if (err == -1) {
			err_dbg(1, err_fmt("personality err"));
			return -1;
		}
		extern char **environ;
		execve(argv[0], argv, environ);
		return 0;
	} else if (fd != 4) {
		err_dbg(0, err_fmt("fd not right, must equal 3 or 4"));
		BUG();
		return -1;
	} else {
		struct stat f3, f4;
		err = fstat(3, &f3);
		if (err == -1) {
			err_dbg(1, err_fmt("fstat err"));
			close(4);
			close(3);
			return -1;
		}
		err = fstat(4, &f4);
		if (err == -1) {
			err_dbg(1, err_fmt("fstat err"));
			close(4);
			close(3);
			return -1;
		}

		if (memcmp(&f3, &f4, sizeof(f3))) {
			err_dbg(0, err_fmt("fd[3] and fd[4] seem not to be same"));
			close(4);
			close(3);
			return -1;
		}
		close(4);
		close(3);
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
