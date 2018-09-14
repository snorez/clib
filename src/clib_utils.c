#include "../include/clib_utils.h"

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
