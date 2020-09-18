#include "./testsuite.h"

void test_compare_bits(void)
{
	char char_s = -1/* , _char_s = 1 */;
	unsigned char char_us = -1/* , _char_us = 1 */;
#if 0
	short short_s = -1, _short_s = 1;
	unsigned short short_us = -1, _short_us = 1;
#endif

	int int_s = -1, _int_s = 1;
	unsigned int int_us = -1, _int_us = 1;
	long long_s = -1, _long_s = 1;
	unsigned long long_us = -1, _long_us = 1;

	int err;
	s64 retval;
	ts_output(1, stdout, "(char_s > int_s) = %d\n", char_s > int_s);
	ts_output(1, stdout, "(char_s == int_s) = %d\n", char_s == int_s);
	err = clib_compute_bits(&char_s, 1, 1, &int_s, 4, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? int_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _int_s) = %d\n", char_s > _int_s);
	ts_output(1, stdout, "(char_s == _int_s) = %d\n", char_s == _int_s);
	err = clib_compute_bits(&char_s, 1, 1, &_int_s, 4, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? _int_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > int_s) = %d\n", char_us > int_s);
	ts_output(1, stdout, "(char_us == int_s) = %d\n", char_us == int_s);
	err = clib_compute_bits(&char_us, 1, 0, &int_s, 4, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? int_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _int_s) = %d\n", char_us > _int_s);
	ts_output(1, stdout, "(char_us == _int_s) = %d\n", char_us == _int_s);
	err = clib_compute_bits(&char_us, 1, 0, &_int_s, 4, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? _int_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > int_us) = %d\n", char_s > int_us);
	ts_output(1, stdout, "(char_s == int_us) = %d\n", char_s == int_us);
	err = clib_compute_bits(&char_s, 1, 1, &int_us, 4, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? int_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _int_us) = %d\n", char_s > _int_us);
	ts_output(1, stdout, "(char_s == _int_us) = %d\n", char_s == _int_us);
	err = clib_compute_bits(&char_s, 1, 1, &_int_us, 4, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? _int_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > int_us) = %d\n", char_us > int_us);
	ts_output(1, stdout, "(char_us == int_us) = %d\n", char_us == int_us);
	err = clib_compute_bits(&char_us, 1, 0, &int_us, 4, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? int_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _int_us) = %d\n", char_us > _int_us);
	ts_output(1, stdout, "(char_us == _int_us) = %d\n", char_us == _int_us);
	err = clib_compute_bits(&char_us, 1, 0, &_int_us, 4, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? _int_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > long_s) = %d\n", char_s > long_s);
	ts_output(1, stdout, "(char_s == long_s) = %d\n", char_s == long_s);
	err = clib_compute_bits(&char_s, 1, 1, &long_s, 8, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? long_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _long_s) = %d\n", char_s > _long_s);
	ts_output(1, stdout, "(char_s == _long_s) = %d\n", char_s == _long_s);
	err = clib_compute_bits(&char_s, 1, 1, &_long_s, 8, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? _long_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > long_s) = %d\n", char_us > long_s);
	ts_output(1, stdout, "(char_us == long_s) = %d\n", char_us == long_s);
	err = clib_compute_bits(&char_us, 1, 0, &long_s, 8, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? long_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _long_s) = %d\n", char_us > _long_s);
	ts_output(1, stdout, "(char_us == _long_s) = %d\n", char_us == _long_s);
	err = clib_compute_bits(&char_us, 1, 0, &_long_s, 8, 1,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? _long_s) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > long_us) = %d\n", char_s > long_us);
	ts_output(1, stdout, "(char_s == long_us) = %d\n", char_s == long_us);
	err = clib_compute_bits(&char_s, 1, 1, &long_us, 8, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? long_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _long_us) = %d\n", char_s > _long_us);
	ts_output(1, stdout, "(char_s == _long_us) = %d\n", char_s == _long_us);
	err = clib_compute_bits(&char_s, 1, 1, &_long_us, 8, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_s ? _long_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > long_us) = %d\n", char_us > long_us);
	ts_output(1, stdout, "(char_us == long_us) = %d\n", char_us == long_us);
	err = clib_compute_bits(&char_us, 1, 0, &long_us, 8, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? long_us) = %d\n", retval);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _long_us) = %d\n", char_us > _long_us);
	ts_output(1, stdout, "(char_us == _long_us) = %d\n", char_us == _long_us);
	err = clib_compute_bits(&char_us, 1, 0, &_long_us, 8, 0,
				CLIB_COMPUTE_F_COMPARE, &retval);
	(void)err;
	ts_output(1, stdout, "(char_us ? _long_us) = %d\n", retval);
}
