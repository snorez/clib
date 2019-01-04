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

#define clib__round_mask(x, y)	((__typeof__(x))((y)-1))
#define clib_round_up(x, y)	((((x)-1)|clib__round_mask(x, y)) + 1)
#define clib_round_down(x, y)	((x) & ~clib__round_mask(x, y))

extern uint32_t min_32(uint32_t a, uint32_t b);
extern uint64_t min_64(uint64_t a, uint64_t b);
extern uint32_t max_32(uint32_t a, uint32_t b);
extern uint64_t max_64(uint64_t a, uint64_t b);

extern void *malloc_s(size_t size);
extern void free_s(void **addr);
extern int hex2int(char *hex);
extern int no_aslr(int argc, char *argv[]);
extern int tmp_close_std(int close_fd);
extern int restore_std(int closed_fd);
extern int output_tmp_std(void);
extern long get_memory_avail(void);
extern void time_acct_start(void);
extern void time_acct_end(void);
extern int clib_open(const char *pathname, int flags, ...);
extern ssize_t clib_read(int fd, void *buf, size_t count);
extern ssize_t clib_write(int fd, void *buf, size_t count);
extern char *clib_ap_start(const char *fmt, ...);
extern void clib_ap_end(char *p);

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

DECL_END

#endif /* end of include guard: UTILS_H_NOWJRQGI */
