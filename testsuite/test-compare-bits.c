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

	int res;
	ts_output(1, stdout, "(char_s > int_s) = %d\n", char_s > int_s);
	ts_output(1, stdout, "(char_s == int_s) = %d\n", char_s == int_s);
	res = clib_compare_bits(&char_s, 1, 1, &int_s, 4, 1);
	ts_output(1, stdout, "(char_s ? int_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _int_s) = %d\n", char_s > _int_s);
	ts_output(1, stdout, "(char_s == _int_s) = %d\n", char_s == _int_s);
	res = clib_compare_bits(&char_s, 1, 1, &_int_s, 4, 1);
	ts_output(1, stdout, "(char_s ? _int_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > int_s) = %d\n", char_us > int_s);
	ts_output(1, stdout, "(char_us == int_s) = %d\n", char_us == int_s);
	res = clib_compare_bits(&char_us, 1, 0, &int_s, 4, 1);
	ts_output(1, stdout, "(char_us ? int_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _int_s) = %d\n", char_us > _int_s);
	ts_output(1, stdout, "(char_us == _int_s) = %d\n", char_us == _int_s);
	res = clib_compare_bits(&char_us, 1, 0, &_int_s, 4, 1);
	ts_output(1, stdout, "(char_us ? _int_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > int_us) = %d\n", char_s > int_us);
	ts_output(1, stdout, "(char_s == int_us) = %d\n", char_s == int_us);
	res = clib_compare_bits(&char_s, 1, 1, &int_us, 4, 0);
	ts_output(1, stdout, "(char_s ? int_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _int_us) = %d\n", char_s > _int_us);
	ts_output(1, stdout, "(char_s == _int_us) = %d\n", char_s == _int_us);
	res = clib_compare_bits(&char_s, 1, 1, &_int_us, 4, 0);
	ts_output(1, stdout, "(char_s ? _int_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > int_us) = %d\n", char_us > int_us);
	ts_output(1, stdout, "(char_us == int_us) = %d\n", char_us == int_us);
	res = clib_compare_bits(&char_us, 1, 0, &int_us, 4, 0);
	ts_output(1, stdout, "(char_us ? int_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _int_us) = %d\n", char_us > _int_us);
	ts_output(1, stdout, "(char_us == _int_us) = %d\n", char_us == _int_us);
	res = clib_compare_bits(&char_us, 1, 0, &_int_us, 4, 0);
	ts_output(1, stdout, "(char_us ? _int_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > long_s) = %d\n", char_s > long_s);
	ts_output(1, stdout, "(char_s == long_s) = %d\n", char_s == long_s);
	res = clib_compare_bits(&char_s, 1, 1, &long_s, 8, 1);
	ts_output(1, stdout, "(char_s ? long_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _long_s) = %d\n", char_s > _long_s);
	ts_output(1, stdout, "(char_s == _long_s) = %d\n", char_s == _long_s);
	res = clib_compare_bits(&char_s, 1, 1, &_long_s, 8, 1);
	ts_output(1, stdout, "(char_s ? _long_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > long_s) = %d\n", char_us > long_s);
	ts_output(1, stdout, "(char_us == long_s) = %d\n", char_us == long_s);
	res = clib_compare_bits(&char_us, 1, 0, &long_s, 8, 1);
	ts_output(1, stdout, "(char_us ? long_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _long_s) = %d\n", char_us > _long_s);
	ts_output(1, stdout, "(char_us == _long_s) = %d\n", char_us == _long_s);
	res = clib_compare_bits(&char_us, 1, 0, &_long_s, 8, 1);
	ts_output(1, stdout, "(char_us ? _long_s) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > long_us) = %d\n", char_s > long_us);
	ts_output(1, stdout, "(char_s == long_us) = %d\n", char_s == long_us);
	res = clib_compare_bits(&char_s, 1, 1, &long_us, 8, 0);
	ts_output(1, stdout, "(char_s ? long_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_s > _long_us) = %d\n", char_s > _long_us);
	ts_output(1, stdout, "(char_s == _long_us) = %d\n", char_s == _long_us);
	res = clib_compare_bits(&char_s, 1, 1, &_long_us, 8, 0);
	ts_output(1, stdout, "(char_s ? _long_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > long_us) = %d\n", char_us > long_us);
	ts_output(1, stdout, "(char_us == long_us) = %d\n", char_us == long_us);
	res = clib_compare_bits(&char_us, 1, 0, &long_us, 8, 0);
	ts_output(1, stdout, "(char_us ? long_us) = %d\n", res);
	ts_output(0, stdout, "\n");

	ts_output(1, stdout, "(char_us > _long_us) = %d\n", char_us > _long_us);
	ts_output(1, stdout, "(char_us == _long_us) = %d\n", char_us == _long_us);
	res = clib_compare_bits(&char_us, 1, 0, &_long_us, 8, 0);
	ts_output(1, stdout, "(char_us ? _long_us) = %d\n", res);
}
