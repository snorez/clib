#ifndef CLIB_BITMAP_H_9WTNDSPA
#define CLIB_BITMAP_H_9WTNDSPA

#include "clib_utils.h"
#include "clib_eh.h"
#include "clib_atomic.h"

DECL_BEGIN

struct clib_bitmap {
	u64	cnt;
	u64	map[0];
};

C_SYM struct clib_bitmap *clib_bitmap_create(u64 bits);
C_SYM void clib_bitmap_destroy(struct clib_bitmap *map);
C_SYM s64 clib_bitmap_set(struct clib_bitmap *map, u64 bit);
C_SYM s64 clib_bitmap_clear(struct clib_bitmap *map, u64 bit);
C_SYM s64 clib_bitmap_nonzero(struct clib_bitmap *map, u64 start_bit);
C_SYM s64 clib_bitmap_zero(struct clib_bitmap *map, u64 start_bit);;

DECL_END

#endif /* end of include guard: CLIB_BITMAP_H_9WTNDSPA */
