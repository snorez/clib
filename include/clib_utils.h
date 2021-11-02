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
#ifndef UTILS_H_NOWJRQGI
#define UTILS_H_NOWJRQGI

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/personality.h>
#include <pthread.h>
#include <sched.h>
#include <syscall.h>
#include <linux/capability.h>
#include <linux/ioctl.h>
#include <limits.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <linux/types.h>
#include <time.h>
#include <sys/resource.h>

#ifdef __cplusplus

#define	DECL_BEGIN	extern "C" {
#define DECL_END	}
#define	C_SYM		extern "C"

#else /* !__cplusplus */

#define DECL_BEGIN
#define DECL_END
#define C_SYM		extern

#endif

DECL_BEGIN

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef likely
#define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)		__builtin_expect(!!(x), 0)
#endif
#ifndef __weak
#define	__weak			__attribute__((weak))
#endif
#ifndef __always_inline
#define	__always_inline		inline __attribute__((always_inline))
#endif
#ifndef noinline
#define	noinline		__attribute__((noinline))
#endif
#ifndef __deprecated
#define	__deprecated		__attribute__((deprecated))
#endif
#ifndef __packed
#define	__packed		__attribute__((packed))
#endif
#ifndef __alias
#define	__alias(symbol)		__attribute__((alias(#symbol)))
#endif
#ifndef __maybe_unused
#define	__maybe_unused		__attribute__((unused))
#endif
#ifndef __always_unused
#define	__always_unused		__attribute__((unused))
#endif
#ifndef weak_alias
#define weak_alias(name,aliasname) _weak_alias(name, aliasname)
#define _weak_alias(name,aliasname) \
extern __typeof (name) aliasname __attribute__((weak,alias(#name)))
#endif

#ifndef BITS_PER_UNIT
#define	BITS_PER_UNIT	(8)
#endif

typedef __s8	s8;
typedef __u8	u8;
typedef __s16	s16;
typedef __u16	u16;
typedef __s32	s32;
typedef __u32	u32;
typedef __s64	s64;
typedef __u64	u64;

#define clib__round_mask(x, y)	((__typeof__(x))((y)-1))
#define clib_round_up(x, y)	((((x)-1)|clib__round_mask(x, y)) + 1)
#define clib_round_down(x, y)	((x) & ~clib__round_mask(x, y))

#define	min_t(type, x, y) ({			\
		type __min1 = (x);		\
		type __min2 = (y);		\
		__min1 < __min2 ? __min1 : __min2; })
#define	max_t(type, x, y) ({			\
		type __max1 = (x);		\
		type __max2 = (y);		\
		__max1 > __max2 ? __max1 : __max2; })

#ifndef ARRAY_CNT
#define	ARRAY_CNT(arr)	(sizeof(arr) / sizeof(arr[0]))
#endif

enum clib_compute_flag {
	CLIB_COMPUTE_F_UNK,
	CLIB_COMPUTE_F_COMPARE,
	CLIB_COMPUTE_F_BITIOR,
	CLIB_COMPUTE_F_BITXOR,
	CLIB_COMPUTE_F_BITAND,
	CLIB_COMPUTE_F_BITNOT,
	CLIB_COMPUTE_F_ADD,
	CLIB_COMPUTE_F_SUB,
	CLIB_COMPUTE_F_MUL,
	CLIB_COMPUTE_F_DIV,
	CLIB_COMPUTE_F_MOD,
	CLIB_COMPUTE_F_SHL,
	CLIB_COMPUTE_F_SHR,
	CLIB_COMPUTE_F_ROL,
	CLIB_COMPUTE_F_ROR,
};

extern int hex2int(char *hex);
extern void bin2hex(FILE *s, uint8_t *str, size_t size);
extern int no_aslr(int argc, char *argv[]);
extern int tmp_close_std(int close_fd);
extern int restore_std(int closed_fd);
extern int output_tmp_std(void);
extern long get_memory_avail(void);
extern void time_acct_start(void);
extern void time_acct_end(void);
extern char *clib_ap_buffer(const char *fmt, ...);
extern int bind_on_cpu(int num);
extern void setup_ns(void);
extern void show_cap(int pid);
extern void clib_memset_bits(void *dst, u8 bit_offset, u32 dst_bits, int val);
extern void clib_memcpy_bits(void *dst, u32 dst_bits, void *src, u32 src_bits);
extern uint64_t s_rand64(void);
extern uint32_t s_rand32(void);
extern void rand_sort(int cnt, long *arr);
extern void rand_sort_unsigned(int cnt, unsigned long *arr);
extern long rand_range(long min, long max);
extern void random_bits(void *dst, size_t bits);
extern int clib_int_extend(char *buf, size_t bufbits, void *src,
			   size_t origbits, int sign, int signbit);
extern int clib_get_signbit(char *l, size_t bytes);
typedef s64 cur_max_signint;
typedef u64 cur_max_unsignint;
extern int clib_compute_bits(void *l, size_t lbytes, int lsign,
				void *r, size_t rbytes, int rsign, int flag,
				cur_max_signint *retval);
extern int clib_in_loop(void *arr, size_t arrsz, size_t elemsz,
			int *start, int *end, int *head, int *tail);
extern int set_stacksize(size_t size);

static inline int get_online_cpus(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

static inline char *get_arg(char *argv[], char *target)
{
	int i = 1;
	while (argv[i]) {
		if (strcmp(argv[i], target))
			i++;
		else
			return argv[i+1];
	}
	return NULL;
}

static inline void *clib_memcpy(void *dst, size_t dstlen,
				void *src, size_t srclen)
{
	size_t copylen = dstlen;
	if (copylen > srclen)
		copylen = srclen;
	return memcpy(dst, src, copylen);
}

/* elemsz must be 1 2 4 8... */
static inline void *array_idx_ptr(void *start, size_t elemsz, size_t idx)
{
	return (void *)((char *)start + (elemsz * idx));
}

DECL_END

#endif /* end of include guard: UTILS_H_NOWJRQGI */
