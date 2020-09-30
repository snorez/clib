#include "./testsuite.h"

void test_in_loop(void)
{
	char arr0[] = "abcdbcebcdbce";
	char arr00[] = "abcdbcebcdbceb";
	char arr01[] = "abcdbcebcdbcebc";
	int start = 0, head = -1, tail = -1;
	char next_v0 = 'b';

	int err = 0;
	err = clib_in_loop(arr0, strlen(arr0), 1, &start, &head, &tail, &next_v0);
	ts_output(1, stdout, "arr0#0 %x: %d %d %d %d\n", next_v0, err,
			start, head, tail);

	next_v0 = 'c';
	err = clib_in_loop(arr00, strlen(arr00), 1, &start, &head, &tail, &next_v0);
	ts_output(1, stdout, "arr00#0 %x: %d %d %d %d\n", next_v0, err,
			start, head, tail);

	next_v0 = 'b';
	err = clib_in_loop(arr01, strlen(arr01), 1, &start, &head, &tail, &next_v0);
	ts_output(1, stdout, "arr01#0 %x: %d %d %d %d\n", next_v0, err,
			start, head, tail);

	start = 0;
	head = -1;
	tail = -1;
	next_v0 = 'c';
	err = clib_in_loop(arr0, strlen(arr0), 1, &start, &head, &tail, &next_v0);
	ts_output(1, stdout, "arr0#1 %x: %d %d %d %d\n", next_v0, err,
			start, head, tail);

	long arr1[] = {
		0x41414141, 0x42424242, 0x43434343,
		0x44444444, 0x45454545,
		0x44444444, 0x45454545,
	};
	start = 0;
	head = -1;
	tail = -1;
	long next_v1 = 0x44444444;
	err = clib_in_loop(arr1, sizeof(arr1) / sizeof(arr1[0]), 8, &start, &head, &tail, &next_v1);
	ts_output(1, stdout, "arr1#0 %lx: %d %d %d %d\n", next_v1, err,
			start, head, tail);

	start = 0;
	head = -1;
	tail = -1;
	next_v1 = 0x43434343;
	err = clib_in_loop(arr1, sizeof(arr1) / sizeof(arr1[0]), 8, &start, &head, &tail, &next_v1);
	ts_output(1, stdout, "arr1#1 %lx: %d %d %d %d\n", next_v1, err,
			start, head, tail);

	return;
}
