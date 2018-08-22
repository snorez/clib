#include <string.h>

void *__memcpy_old(void *, const void *, size_t);

#ifndef __x86_64__
asm(".symver memcpy, memcpy@GLIBC_2.0");
#else
asm(".symver memcpy, memcpy@GLIBC_2.2.5");
#endif

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}
