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

static int __do_compare(char *l, char *r, size_t bytes, int sign)
{
	/* TODO: endian? */
	int l_msb_bit = test_bit(7, (long *)&l[bytes-1]);
	int r_msb_bit = test_bit(7, (long *)&r[bytes-1]);

	if (sign) {
		if (l_msb_bit > r_msb_bit)
			return -1;
		else if (l_msb_bit < r_msb_bit)
			return 1;
	} else {
		if (l_msb_bit > r_msb_bit)
			return 1;
		else if (l_msb_bit < r_msb_bit)
			return -1;
	}

	for (size_t i = bytes; i > 0; i--) {
		char *curlb = &l[i-1];
		char *currb = &r[i-1];
		for (int j = 7; j >= 0; j--) {
			int lv, rv;
			lv = test_bit(j, (long *)curlb);
			rv = test_bit(j, (long *)currb);
			if (lv > rv)
				return 1;
			else if (lv < rv)
				return -1;
		}
	}

	return 0;
}

int clib_compare_bits(void *l, size_t lbytes, int lsign,
			void *r, size_t rbytes, int rsign)
{
	size_t compare_bytes = lbytes;
	int compare_sign = lsign;
	if (compare_bytes < rbytes) {
		compare_bytes = rbytes;
		compare_sign = rsign;
	}

	char _l[compare_bytes];
	char _r[compare_bytes];
	int err;

	err = clib_int_extend(_l, compare_bytes * 8, l, lbytes * 8, lsign);
	(void)err;
	err = clib_int_extend(_r, compare_bytes * 8, r, rbytes * 8, rsign);
	(void)err;

	return __do_compare(_l, _r, compare_bytes, compare_sign);
}
