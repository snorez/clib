#ifndef TESTSUITE_H_WCTEQ9S1
#define TESTSUITE_H_WCTEQ9S1

#include <clib.h>

DECL_BEGIN

static inline void ts_output(int ident, FILE *stream, const char *fmt, ...)
{
	char _ident[ident+1];
	for (int i = 0; i < ident; i++)
		_ident[i] = '\t';
	_ident[ident] = 0;
	fprintf(stream, "%s", _ident);
	fflush(stream);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stream, fmt, ap);
	va_end(ap);

	fflush(stream);
}

#endif /* end of include guard: TESTSUITE_H_WCTEQ9S1 */
