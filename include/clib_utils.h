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

extern int hex2int(char *hex);
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
extern long s_random(void);
extern void random_bits(void *dst, size_t bits);
extern int clib_int_extend(char *buf, size_t bufbits, void *src,
			   size_t origbits, int signbit);
extern int clib_compare_bits(void *l, size_t lbytes, int lsign,
				void *r, size_t rbytes, int rsign);

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

static inline void clib_realpath(const char *path, char *resolved_path)
{
	/* XXX: path length should less than PATH_MAX */
	char tmp_path0[PATH_MAX];
	memset(tmp_path0, 0, PATH_MAX);

	char *pb = (char *)path;
	char *pe = (char *)path;
	char *pt = tmp_path0+PATH_MAX-1;
	while (*pe) {
		if (*pe != '/') {
			pe++;
		} else if (pb != pe) {
			size_t cnt;
			cnt = pe - pb;
			memcpy(pt-cnt, pb, cnt);
			pt = pt-cnt-1;
			pe++;
			pb = pe;
		} else {
			pe++;
			pb = pe;
		}
	}

	if (pb != pe) {
		size_t cnt;
		cnt = pe - pb;
		memcpy(pt-cnt, pb, cnt);
	}

	pt = tmp_path0;
	int zero_next = 0;
	size_t count = 0;
	while (pt < (tmp_path0+PATH_MAX)) {
		if (!*pt) {
			pt++;
			continue;
		}

		if (!strcmp("..", pt)) {
			memset(pt, 0, 2);
			pt += 2;
			zero_next++;
			continue;
		}

		if (!strcmp(".", pt)) {
			memset(pt, 0, 1);
			pt += 1;
			continue;
		}

		if (zero_next) {
			memset(pt, 0, strlen(pt));
			pt += strlen(pt);
			zero_next--;
		}

		count += strlen(pt) + 1; /* filename and '/' */
		pt += strlen(pt);
	}

	pt = tmp_path0;
	size_t left = count;
	char *pr = resolved_path+left;
	while (pt < (tmp_path0+PATH_MAX)) {
		if (!*pt) {
			pt++;
			continue;
		}

		size_t cnt = strlen(pt);
		memcpy(pr-cnt, pt, cnt);
		pt += cnt;
		pr = pr-cnt-1;
		*pr = '/';
		left -= (cnt + 1);
		if (!left)
			break;
	}
}

static inline int is_same_path(const char *path0, const char *path1)
{
	if (!strcmp(path0, path1))
		return 1;

	char resolved_path0[PATH_MAX];
	char resolved_path1[PATH_MAX];
	memset(resolved_path0, 0, PATH_MAX);
	memset(resolved_path1, 0, PATH_MAX);

	clib_realpath(path0, resolved_path0);
	clib_realpath(path1, resolved_path1);

	if (!strcmp(resolved_path0, resolved_path1))
		return 1;
	if (!strcmp(resolved_path0, path1))
		return 1;
	if (!strcmp(path0, resolved_path1))
		return 1;

	return 0;
}

static inline void *clib_memcpy(void *dst, size_t dstlen,
				void *src, size_t srclen)
{
	size_t copylen = dstlen;
	if (copylen > srclen)
		copylen = srclen;
	return memcpy(dst, src, copylen);
}

DECL_END

#endif /* end of include guard: UTILS_H_NOWJRQGI */
