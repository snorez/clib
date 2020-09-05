#include "./testsuite.h"

#define	TESTCASE(n)	{#n, n}
#define	TESTCASE_DECL(n) \
C_SYM void n(void)

TESTCASE_DECL(test_slist);

struct testsuite {
	char	*name;
	void	(*callback)(void);
} testsuites[] = {
	/* Edit new testcase here */
	TESTCASE(test_slist),
};

int main(int argc, char *argv[])
{
	struct testsuite *ts;
	for (int i = 0; i < sizeof(testsuites) / sizeof(testsuites[0]); i++) {
		ts = &testsuites[i];

		ts_output(0, stdout, "Testcase: %s\n", ts->name);

		ts->callback();

		ts_output(0, stdout, "Testcase: %s done.\n", ts->name);
	}

	return 0;
}
