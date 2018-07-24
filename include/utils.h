#ifndef UTILS_H_NOWJRQGI
#define UTILS_H_NOWJRQGI

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t min_32(uint32_t a, uint32_t b);
extern uint64_t min_64(uint64_t a, uint64_t b);
extern uint32_t max_32(uint32_t a, uint32_t b);
extern uint64_t max_64(uint64_t a, uint64_t b);

extern void *malloc_s(size_t size);
extern void free_s(void **addr);
extern int hex2int(char *hex);

#endif /* end of include guard: UTILS_H_NOWJRQGI */
