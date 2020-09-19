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
		err_dbg(0, "something goes wrong");
		return -1;
	}

	struct stat f_prev, f_cur;
	err = fstat(fd-1, &f_prev);
	if (err == -1) {
		err_dbg(1, "fstat err");
		close(fd);
		return -1;
	}
	err = fstat(fd, &f_cur);
	if (err == -1) {
		err_dbg(1, "fstat err");
		close(fd);
		return -1;
	}

	if (memcmp(&f_prev, &f_cur, sizeof(f_prev))) {
		err = personality(ADDR_NO_RANDOMIZE);
		if (err == -1) {
			err_dbg(1, "personality err");
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
		err_dbg(1, "dup err");
		return -1;
	}

	int fd = open(tmp_std_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		err_dbg(1, "open err");
		close(tmp_std_fd);
		return -1;
	}

	err = dup2(fd, close_fd);
	if (err != close_fd) {
		err_dbg(1, "dup2 err");
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
		err_dbg(1, "dup2(%d) err", err);
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
		err_dbg(1, "run %s err", cmd);
		return -1;
	}
	return 0;
}

long get_memory_avail(void)
{
	int fd = open("/proc/meminfo", O_RDONLY);
	if (fd == -1) {
		err_dbg(1, "open err");
		return -1;
	}

	char buf[4096];
	memset(buf, 0, 4096);
	int err = read(fd, buf, 4096);
	if (err == -1) {
		err_dbg(1, "read err");
		close(fd);
		return -1;
	}
	close(fd);

	char *string = "MemAvailable:";
	char *p = strstr(buf, string);
	if (!p) {
		err_dbg(0, "MemAvailable not found");
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
		err_dbg(1, "gettimeofday err");
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
		err_dbg(1, "gettimeofday err");
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

char *clib_ap_buffer(const char *fmt, ...)
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

int bind_on_cpu(int num)
{
	cpu_set_t cpu;
	CPU_ZERO(&cpu);
	CPU_SET(num, &cpu);
	if (sched_setaffinity(syscall(SYS_gettid), sizeof(cpu), &cpu) == -1) {
		perror("sched_setaffinity");
		return -1;
	}

	CPU_ZERO(&cpu);
	if (sched_getaffinity(syscall(SYS_gettid), sizeof(cpu), &cpu) == -1) {
		perror("sched_getaffinity");
		return -1;
	}

	if (!CPU_ISSET(num, &cpu))
		return -1;

	return 0;
}

static int __write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return 0;
	if (write(fd, buf, len) != len) {
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}

void setup_ns(void)
{
	int real_uid = getuid();
	int real_gid = getgid();

        if (unshare(CLONE_NEWUSER) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

        if (unshare(CLONE_NEWNET) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!__write_file("/proc/self/setgroups", "deny")) {
		perror("__write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!__write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
		perror("__write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!__write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("__write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo up") != 0) {
		perror("system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}

	printf("[+] namespace sandbox setup successfully\n");
}

void show_cap(int pid)
{
	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = (void *)&cap_header_data;

	struct __user_cap_data_struct cap_data_data[2] = {0};
	cap_user_data_t cap_data = (void *)&cap_data_data;

	cap_header->pid = pid;
	cap_header->version = _LINUX_CAPABILITY_VERSION_3;

	if (syscall(SYS_capget, cap_header, cap_data) < 0) {
		perror("capget");
		return;
	}

	fprintf(stdout, "Cap: %x, %x, %x, %x, %x, %x\n",
			cap_data_data[0].effective,
			cap_data_data[0].permitted,
			cap_data_data[0].inheritable,
			cap_data_data[1].effective,
			cap_data_data[1].permitted,
			cap_data_data[1].inheritable);
	return;
}

/*
 * dest: the address to write
 * bit_offset: the first bit offset of dest[0]
 * dst_bits: total bits to write
 * val: 0 or 1;
 */
void clib_memset_bits(void *dest, u8 bit_offset, u32 dst_bits, int val)
{
	val = val ? 1 : 0;
	u32 bits_left = dst_bits;
	void *wpos = dest;

	if (bit_offset) {
		for (u32 i = bit_offset; i < 8; i++) {
			if (!val)
				test_and_clear_bit(i , (long *)wpos);
			else
				test_and_set_bit(i, (long *)wpos);
		}
		bits_left -= (8 - bit_offset);
		wpos += 1;
	}

	while (bits_left) {
		if (bits_left >= 64) {
			if (!val)
				*(u64 *)wpos = 0;
			else
				*(u64 *)wpos = (u64)-1;
			wpos += 8;
			bits_left -= 64;
		} else if (bits_left >= 32) {
			if (!val)
				*(u32 *)wpos = 0;
			else
				*(u32 *)wpos = (u32)-1;
			wpos += 4;
			bits_left -= 32;
		} else if (bits_left >= 16) {
			if (!val)
				*(u16 *)wpos = 0;
			else
				*(u16 *)wpos = (u16)-1;
			wpos += 2;
			bits_left -= 16;
		} else if (bits_left >= 8) {
			if (!val)
				*(u8 *)wpos = 0;
			else
				*(u8 *)wpos = (u8)-1;
			wpos += 1;
			bits_left -= 8;
		} else {
			for (u32 i = 0; i < bits_left; i++) {
				if (!val)
					test_and_clear_bit(i, (long *)wpos);
				else
					test_and_set_bit(i, (long *)wpos);
			}
			bits_left = 0;
		}
	}
}

void clib_memcpy_bits(void *dest, u32 dst_bits, void *src, u32 src_bits)
{
	void *wpos = dest;
	void *rpos = src;
	u32 bits_left = src_bits;
	if (bits_left > dst_bits)
		bits_left = dst_bits;

	while (bits_left > 8) {
		*(char *)wpos = *(char *)rpos;
		wpos = (void *)((char *)wpos + 1);
		rpos = (void *)((char *)rpos + 1);
		bits_left -= 8;
	}

	for (u32 i = 0; i < bits_left; i++) {
		if (test_bit(i, (long *)rpos))
			test_and_set_bit(i, (long *)wpos);
		else
			test_and_clear_bit(i, (long *)wpos);
	}
}

/*
 * random seed use current systime may not be safe, so
 * libsodium may be a good choice, use randombytes_buf/randombytes_uniform
 * instead
 */
long s_random(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		err_dbg(1, "gettimeofday err");
		srand(random());
		return random();
	}
	srand(tv.tv_sec + tv.tv_usec);
	return random();
}

void random_bits(void *dst, size_t bits)
{
	size_t bits_left = bits;
	void *wpos = dst;
	while (bits_left) {
		if (bits_left >= (sizeof(long) * 8)) {
			long val = s_random();
			*(long *)wpos = val;
			wpos += sizeof(long);
			bits_left -= (sizeof(long) * 8);
		} else if (bits_left >= (sizeof(int) * 8)) {
			long val = s_random();
			*(int *)wpos = (int)val;
			wpos += sizeof(int);
			bits_left -= (sizeof(int) * 8);
		} else if (bits_left >= (sizeof(char) * 8)) {
			long val = s_random();
			*(char *)wpos = (char)val;
			wpos += sizeof(char);
			bits_left -= (sizeof(char) * 8);
		} else {
			for (size_t i = 0; i < bits_left; i++) {
				long val = s_random() % 2;
				if (!val)
					test_and_clear_bit(i, (long *)wpos);
				else
					test_and_set_bit(i, (long *)wpos);
			}
			bits_left = 0;
		}
	}
	return;
}

int clib_int_extend(char *buf, size_t bufbits, void *src, size_t origbits,
			int signbit)
{
	if (bufbits < origbits)
		return -1;

	clib_memset_bits(buf, 0, bufbits, 0);
	clib_memcpy_bits(buf, bufbits, src, origbits);
	clib_memset_bits(buf + (origbits / 8), (origbits % 8),
			 bufbits - origbits, signbit);
	return 0;
}

static int __do_compare(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	/* TODO: endian? */
	int l_msb_bit = test_bit(7, (long *)&l[bytes-1]);
	int r_msb_bit = test_bit(7, (long *)&r[bytes-1]);

	if (sign) {
		if (l_msb_bit > r_msb_bit) {
			*retval = -1;
			return 0;
		} else if (l_msb_bit < r_msb_bit) {
			*retval = 1;
			return 0;
		}
	} else {
		if (l_msb_bit > r_msb_bit) {
			*retval = 1;
			return 0;
		} else if (l_msb_bit < r_msb_bit) {
			*retval = -1;
			return 0;
		}
	}

	for (size_t i = bytes; i > 0; i--) {
		char *curlb = &l[i-1];
		char *currb = &r[i-1];
		for (int j = 7; j >= 0; j--) {
			int lv, rv;
			lv = test_bit(j, (long *)curlb);
			rv = test_bit(j, (long *)currb);
			if (lv > rv) {
				*retval = 1;
				return 0;
			} else if (lv < rv) {
				*retval = -1;
				return 0;
			}
		}
	}

	*retval = 0;
	return 0;
}

static int __do_bitior(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	char *_ret = (char *)retval;
	for (size_t i = 0; i < bytes; i++) {
		_ret[i] = l[i] | r[i];
	}
	return 0;
}

static int __do_bitxor(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	char *_ret = (char *)retval;
	for (size_t i = 0; i < bytes; i++) {
		_ret[i] = l[i] ^ r[i];
	}
	return 0;
}

static int __do_bitand(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	char *_ret = (char *)retval;
	for (size_t i = 0; i < bytes; i++) {
		_ret[i] = l[i] & r[i];
	}
	return 0;
}

#define	__do_arithmetic_X(type, l, r, retval, op) \
	do {\
		type _l = *(type *)l;\
		type _r = *(type *)r;\
		switch (op) {\
		case 1:\
		{\
			*retval = (cur_max_signint)(_l + _r);\
			return 0;\
		}\
		case 2:\
		{\
			*retval = (cur_max_signint)(_l - _r);\
			return 0;\
		}\
		case 3:\
		{\
			*retval = (cur_max_signint)(_l * _r);\
			return 0;\
		}\
		case 4:\
		{\
			if (!_r) {\
				err_dbg(0, "div zero\n");\
				return -1;\
			}\
			*retval = (cur_max_signint)(_l / _r);\
			return 0;\
		}\
		default:\
		{\
			err_dbg(0, "should not happend\n");\
			return -1;\
		}\
		}\
	} while (0)

static int __do_arithmetic_1_signed(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(char, l, r, retval, op);
}

static int __do_arithmetic_1_unsigned(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(unsigned char, l, r, retval, op);
}

static int __do_arithmetic_2_signed(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(short, l, r, retval, op);
}

static int __do_arithmetic_2_unsigned(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(unsigned short, l, r, retval, op);
}

static int __do_arithmetic_4_signed(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(int, l, r, retval, op);
}

static int __do_arithmetic_4_unsigned(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(unsigned int, l, r, retval, op);
}

static int __do_arithmetic_8_signed(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(long, l, r, retval, op);
}

static int __do_arithmetic_8_unsigned(char *l, char *r, cur_max_signint *retval,
					int op)
{
	__do_arithmetic_X(unsigned long, l, r, retval, op);
}

/*
 * @op:
 *	1: add
 *	2: sub
 *	3: mul
 *	4: div
 */
static int __do_arithmetic(char *l, char *r, size_t bytes, int sign,
				cur_max_signint *retval, int op)
{
	switch (bytes) {
	case 1:
	{
		if (sign)
			return __do_arithmetic_1_signed(l, r, retval, op);
		else
			return __do_arithmetic_1_unsigned(l, r, retval, op);
	}
	case 2:
	{
		if (sign)
			return __do_arithmetic_2_signed(l, r, retval, op);
		else
			return __do_arithmetic_2_unsigned(l, r, retval, op);
	}
	case 4:
	{
		if (sign)
			return __do_arithmetic_4_signed(l, r, retval, op);
		else
			return __do_arithmetic_4_unsigned(l, r, retval, op);
	}
	case 8:
	{
		if (sign)
			return __do_arithmetic_8_signed(l, r, retval, op);
		else
			return __do_arithmetic_8_unsigned(l, r, retval, op);
	}
	default:
	{
		err_dbg(0, "bytes %ld not handled\n", bytes);
		return -1;
	}
	}
}

static int __do_add(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_arithmetic(l, r, bytes, sign, retval, 1);
}

static int __do_sub(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_arithmetic(l, r, bytes, sign, retval, 2);
}

static int __do_mul(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_arithmetic(l, r, bytes, sign, retval, 3);
}

static int __do_div(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_arithmetic(l, r, bytes, sign, retval, 4);
}

static int __do_shift(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval, int dir)
{
	cur_max_signint shift_cnt;
	cur_max_signint orig_val;
	switch (bytes) {
	case 1:
	{
		if (sign) {
			char _lc = *(char *)l;
			char _rc = *(char *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		} else {
			unsigned char _lc = *(unsigned char *)l;
			unsigned char _rc = *(unsigned char *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		}
		break;
	}
	case 2:
	{
		if (sign) {
			short _lc = *(short *)l;
			short _rc = *(short *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		} else {
			unsigned short _lc = *(unsigned short *)l;
			unsigned short _rc = *(unsigned short *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		}
		break;
	}
	case 4:
	{
		if (sign) {
			int _lc = *(int *)l;
			int _rc = *(int *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		} else {
			unsigned int _lc = *(unsigned int *)l;
			unsigned int _rc = *(unsigned int *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		}
		break;
	}
	case 8:
	{
		if (sign) {
			long _lc = *(long *)l;
			long _rc = *(long *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		} else {
			unsigned long _lc = *(unsigned long *)l;
			unsigned long _rc = *(unsigned long *)r;
			orig_val = (cur_max_signint)_lc;
			shift_cnt = (cur_max_signint)_rc;
		}
		break;
	}
	default:
	{
		err_dbg(0, "bytes %ld not handled\n", bytes);
		return -1;
	}
	}

	if (!dir)
		*retval = orig_val << shift_cnt;
	else
		if (sign)
			*retval = orig_val >> shift_cnt;
		else
			*retval = (cur_max_unsignint)orig_val >> shift_cnt;
	return 0;
}

static int __do_shl(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_shift(l, r, bytes, sign, retval, 0);
}

static int __do_shr(char *l, char *r, size_t bytes, int sign,
			cur_max_signint *retval)
{
	return __do_shift(l, r, bytes, sign, retval, 1);
}

static struct {
	int	flag;
	int	(*callback)(char *, char *, size_t, int, cur_max_signint *);
} compute_cbs[] = {
	{CLIB_COMPUTE_F_COMPARE, __do_compare},
	{CLIB_COMPUTE_F_BITIOR, __do_bitior},
	{CLIB_COMPUTE_F_BITXOR, __do_bitxor},
	{CLIB_COMPUTE_F_BITAND, __do_bitand},
	{CLIB_COMPUTE_F_ADD, __do_add},
	{CLIB_COMPUTE_F_SUB, __do_sub},
	{CLIB_COMPUTE_F_MUL, __do_mul},
	{CLIB_COMPUTE_F_DIV, __do_div},
	{CLIB_COMPUTE_F_SHL, __do_shl},
	{CLIB_COMPUTE_F_SHR, __do_shr},
#if 0
	{CLIB_COMPUTE_F_ROL, __do_rol},
	{CLIB_COMPUTE_F_ROR, __do_ror},
#endif
};
/*
 * return value:
 *	-1: error occured
 *	0: success
 */
int clib_compute_bits(void *l, size_t lbytes, int lsign,
			void *r, size_t rbytes, int rsign,
			int flag, cur_max_signint *retval)
{
	size_t compute_bytes = lbytes;
	int compute_sign = lsign;
	if (compute_bytes < rbytes) {
		compute_bytes = rbytes;
		compute_sign = rsign;
	} else if (compute_bytes == rbytes) {
		if (!lsign)
			compute_sign = lsign;
		else if (!rsign)
			compute_sign = rsign;
	}

	if (compute_bytes > sizeof(*retval)) {
		err_dbg(0, "params should not be large than 64bits\n");
		return -1;
	}

	char _l[compute_bytes];
	char _r[compute_bytes];
	int err;

	err = clib_int_extend(_l, compute_bytes * 8, l, lbytes * 8, lsign);
	(void)err;
	err = clib_int_extend(_r, compute_bytes * 8, r, rbytes * 8, rsign);
	(void)err;

	for (size_t i = 0; i < sizeof(compute_cbs) / sizeof(compute_cbs[0]);
			i++) {
		if (compute_cbs[i].flag != flag)
			continue;
		return compute_cbs[i].callback(_l, _r, compute_bytes,
						compute_sign, retval);
	}
		
	err_dbg(0, "%d not implemented yet\n", flag);
	return -1;
}
