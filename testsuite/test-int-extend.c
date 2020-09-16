#include "./testsuite.h"

struct test {
	unsigned long	a: 8;
	long		b: 14;
	int		pad: 2;
	unsigned	c: 16;
};

void test_int_extend(void)
{
	struct test test;
	memset(&test, 0xff, sizeof(test));

	ts_output(1, stdout, "Value should be: test.a(%d) test.b(%d) "
			"test.c(%d)\n",
			(unsigned long)0xff,
			(long)-1,
			(unsigned)0xffff);

	unsigned long v;
	int err;

	err = clib_int_extend((char *)&v, sizeof(v) * 8, ((char *)&test), 8, 0);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.a 0) result: %lx\n", v);

	err = clib_int_extend((char *)&v, sizeof(v) * 8, ((char *)&test), 8, 1);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.a 1) result: %lx\n", v);

	err = clib_int_extend((char *)&v, sizeof(v) * 8,
				((char *)&test + 1), 14, 0);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.b 0) result: %lx\n", v);

	err = clib_int_extend((char *)&v, sizeof(v) * 8,
				((char *)&test + 1), 14, 1);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.b 1) result: %lx\n", v);

	err = clib_int_extend((char *)&v, sizeof(v) * 8,
				((char *)&test + 3), 16, 0);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.c 0) result: %lx\n", v);

	err = clib_int_extend((char *)&v, sizeof(v) * 8,
				((char *)&test + 3), 16, 1);
	(void)err;
	ts_output(1, stdout, "clib_int_extend(test.c 1) result: %lx\n", v);
}
