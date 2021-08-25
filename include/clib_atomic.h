/*
 * most come from linux kernel
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
#ifndef ATOMIC_H_ED79JAJV
#define ATOMIC_H_ED79JAJV

#if !defined __clang__ && !defined __GNUC__
#error "please use GCC"
#endif

#ifdef __clang__
extern void __atomic_store_8(volatile long *, long, int);
extern long __atomic_load_8(volatile long *, int);
extern long __atomic_exchange_8(volatile long *, long, int);
#endif

#include "../include/clib_utils.h"

DECL_BEGIN

#ifdef __x86_64__
#define CONFIG_X86_64
#define CONFIG_64BIT
#else
#error "only support on x86_64"
#endif

#define CONFIG_SMP

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
#endif

/* Exception table entry */
#ifdef __ASSEMBLY__
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	.pushsection "__ex_table","a" ;				\
	.balign 4 ;						\
	.long (from) - . ;					\
	.long (to) - . ;					\
	.long (handler) - . ;					\
	.popsection

# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)

# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)

# define _ASM_EXTABLE_EX(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_ext)

# define _ASM_NOKPROBE(entry)					\
	.pushsection "_kprobe_blacklist","aw" ;			\
	_ASM_ALIGN ;						\
	_ASM_PTR (entry);					\
	.popsection

.macro ALIGN_DESTINATION
	/* check for bad alignment of destination */
	movl %edi,%ecx
	andl $7,%ecx
	jz 102f				/* already aligned */
	subl $8,%ecx
	negl %ecx
	subl %ecx,%edx
100:	movb (%rsi),%al
101:	movb %al,(%rdi)
	incq %rsi
	incq %rdi
	decl %ecx
	jnz 100b
102:
	.section .fixup,"ax"
103:	addl %ecx,%edx			/* ecx is zerorest also */
	jmp copy_user_handle_tail
	.previous

	_ASM_EXTABLE(100b,103b)
	_ASM_EXTABLE(101b,103b)
	.endm

#else
# define _EXPAND_EXTABLE_HANDLE(x) #x
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	" .pushsection \"__ex_table\",\"a\"\n"			\
	" .balign 4\n"						\
	" .long (" #from ") - .\n"				\
	" .long (" #to ") - .\n"				\
	" .long (" _EXPAND_EXTABLE_HANDLE(handler) ") - .\n"	\
	" .popsection\n"

# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)

# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)

# define _ASM_EXTABLE_EX(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_ext)

/* For C file, we already have NOKPROBE_SYMBOL macro */
#endif

/* XXX:copy from arch/x86/include/asm/rmwcc.h */
#if !defined(__GCC_ASM_FLAG_OUTPUTS__) && defined(CC_HAVE_ASM_GOTO)

/* Use asm goto */

#define __GEN_RMWcc(fullop, var, cc, ...)				\
do {									\
	asm_volatile_goto (fullop "; j" #cc " %l[cc_label]"		\
			: : "m" (var), ## __VA_ARGS__ 			\
			: "memory" : cc_label);				\
	return 0;							\
cc_label:								\
	return 1;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, arg0, cc) 				\
	__GEN_RMWcc(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, vcon, val, arg0, cc)			\
	__GEN_RMWcc(op " %1, " arg0, var, cc, vcon (val))

#else /* defined(__GCC_ASM_FLAG_OUTPUTS__) || !defined(CC_HAVE_ASM_GOTO) */

/* Use flags output or a set instruction */

#define __GEN_RMWcc(fullop, var, cc, ...)				\
do {									\
	bool c;								\
	asm volatile (fullop ";" CC_SET(cc)				\
			: "+m" (var), CC_OUT(cc) (c)			\
			: __VA_ARGS__ : "memory");			\
	return c;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, arg0, cc)				\
	__GEN_RMWcc(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, vcon, val, arg0, cc)			\
	__GEN_RMWcc(op " %2, " arg0, var, cc, vcon (val))

#endif /* defined(__GCC_ASM_FLAG_OUTPUTS__) || !defined(CC_HAVE_ASM_GOTO) */

/* XXX: copy from arch/x86/include/asm/barrier.h */
#ifdef CONFIG_X86_32
#define mb() asm volatile(ALTERNATIVE("lock; addl $0,0(%%esp)", "mfence", \
				      X86_FEATURE_XMM2) ::: "memory", "cc")
#define rmb() asm volatile(ALTERNATIVE("lock; addl $0,0(%%esp)", "lfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")
#define wmb() asm volatile(ALTERNATIVE("lock; addl $0,0(%%esp)", "sfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")
#else
#define mb() 	asm volatile("mfence":::"memory")
#define rmb()	asm volatile("lfence":::"memory")
#define wmb()	asm volatile("sfence" ::: "memory")
#endif

#ifdef CONFIG_SMP
#define LOCK_PREFIX_HERE \
		".pushsection .smp_locks,\"a\"\n"	\
		".balign 4\n"				\
		".long 671f - .\n" /* offset */		\
		".popsection\n"				\
		"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#else /* ! CONFIG_SMP */
#define LOCK_PREFIX_HERE ""
#define LOCK_PREFIX ""
#endif

/*
 * use atomic_t as mutex/rw_lock, also refcount
 * as refcount, the 0bit is control bit
 * as lock, the 0bit is mutex, 1-3bit is rwlock
 */
typedef struct {
	volatile long counter;
} atomic_t;

typedef atomic_t lock_t;
typedef atomic_t ref_t;

#define	CONFIG_USE_PTHREAD_LOCK
#ifndef CONFIG_USE_PTHREAD_LOCK
typedef lock_t mutex_t;
typedef lock_t rwlock_t;
#define	MUTEX_INIT_V	0
#define	RWLOCK_INIT_V	0
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
typedef pthread_rwlock_t rwlock_t;
#define	MUTEX_INIT_V	PTHREAD_MUTEX_INITIALIZER
#define	RWLOCK_INIT_V	PTHREAD_RWLOCK_INITIALIZER
#endif

#ifndef __cplusplus
typedef _Bool	bool;
#ifndef true
#define true (!(0))
#endif
#ifndef false
#define false (!(1))
#endif
#endif
typedef unsigned long size_t;

static __always_inline bool test_and_set_bit(long nr, volatile long *addr)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "bts", *addr, "Ir", nr, "%0", c);
}

static __always_inline bool test_and_clear_bit(long nr, volatile long *addr)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "btr", *addr, "Ir", nr, "%0", c);
}

static __always_inline bool test_bit(long nr, volatile long *addr)
{
	bool oldbit;

	asm volatile("btq %2,%1"
			CC_SET(c)
			: CC_OUT(c) (oldbit)
			: "m" (*(unsigned long *)addr), "Ir" (nr));

	return oldbit;
}

static __always_inline void atomic_set(atomic_t *v, long i)
{
	__atomic_store_8(&v->counter, i, __ATOMIC_SEQ_CST);
}

static __always_inline long atomic_read(atomic_t *v)
{
	return __atomic_load_8(&v->counter, __ATOMIC_SEQ_CST);
}

static __always_inline long atomic_set_return(atomic_t *v, long i)
{
	return __atomic_exchange_8(&v->counter, i, __ATOMIC_SEQ_CST);
}
/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static __always_inline void atomic_add(long i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "add %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __always_inline void atomic_sub(long i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "sub %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static __always_inline bool atomic_sub_and_test(long i, atomic_t *v)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "sub", v->counter, "er", i, "%0", e);
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static __always_inline void atomic_inc(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "incl %0"
		     : "+m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static __always_inline void atomic_dec(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "decl %0"
		     : "+m" (v->counter));
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static __always_inline bool atomic_dec_and_test(atomic_t *v)
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "decl", v->counter, "%0", e);
}

/**
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static __always_inline bool atomic_inc_and_test(atomic_t *v)
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "inc", v->counter, "%0", e);
}

/**
 * atomic_add_negative - add and test if negative
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
static __always_inline bool atomic_add_negative(long i, atomic_t *v)
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "add", v->counter, "er", i, "%0", s);
}

#define nop() do { asm volatile ("nop"); } while(0)
static __always_inline void do_nop(size_t times)
{
	while (times--)
		nop();
}

#ifndef CONFIG_USE_PTHREAD_LOCK
static __always_inline int mutex_init(mutex_t *v)
{
	atomic_set(v, MUTEX_INIT_V);
	return 0;
}

static __always_inline bool mutex_lock_bit(mutex_t *v, size_t bit)
{
	while (test_and_set_bit(bit, &v->counter))
		do_nop(0x10);
	return true;
}

static __always_inline int mutex_lock(mutex_t *v)
{
	return mutex_lock_bit(v, 0);
}

static __always_inline void mutex_unlock_bit(mutex_t *v, size_t bit)
{
	test_and_clear_bit(bit, &v->counter);
}

static __always_inline int mutex_unlock(mutex_t *v)
{
	mutex_unlock_bit(v, 0);
}

static __always_inline bool mutex_lock_timeout(mutex_t *v, size_t times)
{
	bool ret = false;
	if (!times)
		return mutex_lock(v);

	times = clib_round_up(times, 0x10);
	while (test_and_set_bit(0, &v->counter)) {
		do_nop(0x10);
		times -= 0x10;
		if (!times)
			break;
	}
	if (times)
		ret = true;
	return ret;
}

static __always_inline int mutex_try_lock(mutex_t *v)
{
	if (test_and_set_bit(0, &v->counter))
		return false;
	return true;
}

static __always_inline int mutex_destroy(mutex_t *v)
{
	return 0;
}
#else
static __always_inline int mutex_init(mutex_t *v)
{
	return pthread_mutex_init(v, NULL);
}

static __always_inline int mutex_lock(mutex_t *v)
{
	return pthread_mutex_lock(v);
}

static __always_inline int mutex_try_lock(mutex_t *v)
{
	return pthread_mutex_trylock(v) == 0;
}

static __always_inline int mutex_unlock(mutex_t *v)
{
	return pthread_mutex_unlock(v);
}

static __always_inline int mutex_destroy(mutex_t *v)
{
	return pthread_mutex_destroy(v);
}
#endif

#ifndef CONFIG_USE_PTHREAD_LOCK
static __always_inline int rwlock_init(rwlock_t *v)
{
	atomic_set(v, RWLOCK_INIT_V);
	return 0;
}

static __always_inline int read_lock(rwlock_t *v)
{
	while (1) {
		mutex_lock_bit(v, 1);
		unsigned long val = (atomic_read(v) >> 2) & 0x3;
		if (!val) {
			test_and_set_bit(2, &v->counter);
			test_and_clear_bit(3, &v->counter);
			atomic_add(1<<4, v);
			mutex_unlock_bit(v, 1);
			return 0;
		} else if (val == 1) {
			atomic_add(1<<4, v);
			mutex_unlock_bit(v, 1);
			return 0;
		} else {
			mutex_unlock_bit(v, 1);
			do_nop(0x10);
		}
	}
}

static __always_inline int read_try_lock(rwlock_t *v)
{
	mutex_lock_bit(v, 1);
	unsigned long val = (atomic_read(v) >> 2) & 0x3;
	if (!val) {
		test_and_set_bit(2, &v->counter);
		test_and_clear_bit(3, &v->counter);
		atomic_add(1<<4, v);
		mutex_unlock_bit(v, 1);
		return 0;
	} else if (val == 1) {
		atomic_add(1<<4, v);
		mutex_unlock_bit(v, 1);
		return 0;
	} else {
		mutex_unlock_bit(v, 1);
		return -1;
	}
}

static __always_inline int write_lock(rwlock_t *v)
{
	while (1) {
		mutex_lock_bit(v, 1);
		unsigned long val = (atomic_read(v) >> 2) & 0x3;
		if (!val) {
			test_and_set_bit(2, &v->counter);
			test_and_set_bit(3, &v->counter);
			mutex_unlock_bit(v, 1);
			return 0;
		} else {
			mutex_unlock_bit(v, 1);
			do_nop(0x10);
		}
	}
}

static __always_inline int write_try_lock(rwlock_t *v)
{
	mutex_lock_bit(v, 1);
	unsigned long val = (atomic_read(v) >> 2) & 0x3;
	if (!val) {
		test_and_set_bit(2, &v->counter);
		test_and_set_bit(3, &v->counter);
		mutex_unlock_bit(v, 1);
		return 0;
	} else {
		mutex_unlock_bit(v, 1);
		return -1;
	}
}

static __always_inline int read_unlock(rwlock_t *v)
{
	mutex_lock_bit(v, 1);
	unsigned long val = (atomic_read(v) >> 2) & 0x3;
	if (val == 0x01) {
		if (!(atomic_read(v) >> 4)) {
			test_and_clear_bit(2, &v->counter);
			test_and_clear_bit(3, &v->counter);
			mutex_unlock_bit(v, 1);
			return 0;
		}
		atomic_sub(1<<4, v);
		if (!(atomic_read(v) >> 4)) {
			test_and_clear_bit(2, &v->counter);
			test_and_clear_bit(3, &v->counter);
		}
	}
	mutex_unlock_bit(v, 1);
	return 0;
}

static __always_inline int write_unlock(rwlock_t *v)
{
	mutex_lock_bit(v, 1);
	unsigned long val = (atomic_read(v) >> 2) & 0x3;
	if (val == 0x3) {
		test_and_clear_bit(2, &v->counter);
		test_and_clear_bit(3, &v->counter);
	}
	mutex_unlock_bit(v, 1);
	return 0;
}

static __always_inline int rwlock_destroy(rwlock_t *v)
{
	return 0;
}
#else
static __always_inline int rwlock_init(rwlock_t *v)
{
	return pthread_rwlock_init(v, NULL);
}

static __always_inline int read_lock(rwlock_t *v)
{
	return pthread_rwlock_rdlock(v);
}

static __always_inline int read_try_lock(rwlock_t *v)
{
	return pthread_rwlock_tryrdlock(v);
}

static __always_inline int write_lock(rwlock_t *v)
{
	return pthread_rwlock_wrlock(v);
}

static __always_inline int write_try_lock(rwlock_t *v)
{
	return pthread_rwlock_trywrlock(v);
}

static __always_inline int read_unlock(rwlock_t *v)
{
	return pthread_rwlock_unlock(v);
}

static __always_inline int write_unlock(rwlock_t *v)
{
	return pthread_rwlock_unlock(v);
}

static __always_inline int rwlock_destroy(rwlock_t *v)
{
	return pthread_rwlock_destroy(v);
}
#endif

#ifndef CONFIG_USE_PTHREAD_LOCK
static __always_inline bool ref_inc_not_zero(ref_t *v)
{
	bool ret = true;
	mutex_lock_bit(v, 0);
	unsigned long val = atomic_read(v) | 1;
	if ((val == (unsigned long)-1) || (val == 1)) {
		ret = false;
	} else {
		atomic_add(1<<1, v);
	}
	mutex_unlock_bit(v, 0);
	return ret;
}

static __always_inline bool ref_dec_and_test(ref_t *v)
{
	bool ret = false;
	mutex_lock_bit(v, 0);
	unsigned long val = atomic_read(v) >> 1;
	if (!val) {
		ret = true;
	} else {
		atomic_sub(1<<1, v);
		if (val == 1)
			ret = true;
	}
	mutex_unlock_bit(v, 0);
	return ret;
}

static __always_inline void ref_set(ref_t *v, size_t val)
{
	mutex_lock_bit(v, 0);
	atomic_set(v, val<<1);
	mutex_unlock_bit(v, 0);
}
#endif

DECL_END

#endif /* end of include guard: ATOMIC_H_ED79JAJV */
