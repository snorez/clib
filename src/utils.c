#include "../include/utils.h"

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
