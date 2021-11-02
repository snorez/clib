#include "testsuite.h"

void test_heap_audit(void)
{
	clib_heap_audit_enable();
	void *p = CLIB_HEAP_AUDIT_ALLOC(3);
	memcpy(CLIB_HEAP_AUDIT(p, 0, 4), "hell", 4);
	CLIB_HEAP_AUDIT_FREE(p);
}
