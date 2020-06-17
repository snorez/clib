#include "../include/clib_bitmap.h"

struct clib_bitmap *clib_bitmap_create(u64 bits)
{
	u64 cnt, len;
	struct clib_bitmap *ret;

	int one_more = (bits % (sizeof(ret->map[0]) * 8)) ? 1 : 0;
	cnt = bits / (sizeof(ret->map[0]) * 8) + one_more;
	len = sizeof(*ret) + cnt * sizeof(ret->map[0]);
	ret = (struct clib_bitmap *)malloc(len);
	if (!ret) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(ret, 0, len);

	ret->cnt = cnt;
	return ret;
}

void clib_bitmap_destroy(struct clib_bitmap *map)
{
	free(map);
}

static s64 clib_bitmap_modify(struct clib_bitmap *map, u64 bit, int clear)
{
	u64 idx = bit / (8 * sizeof(map->map[0]));
	u64 bit_nr = bit % (8 * sizeof(map->map[0]));
	void *target;

	if (idx >= map->cnt) {
		err_dbg(0, "target bit exceed the total length.");
		return -1;
	}

	target = &map->map[idx];
	if (clear)
		return test_and_clear_bit(bit_nr, target);
	else
		return test_and_set_bit(bit_nr, target);
}

s64 clib_bitmap_set(struct clib_bitmap *map, u64 bit)
{
	return clib_bitmap_modify(map, bit, 0);
}

s64 clib_bitmap_clear(struct clib_bitmap *map, u64 bit)
{
	return clib_bitmap_modify(map, bit, 1);
}

static s64 clib_bitmap_find_next(struct clib_bitmap *map, u64 start_bit,
				 int val)
{
	u64 idx = start_bit / (8 * sizeof(map->map[0]));
	u64 bit_nr = start_bit % (8 * sizeof(map->map[0]));
	s64 ret = -1;
	int shifted = 0;
	val = !!val;

	for (; idx < map->cnt; idx++) {
		u64 v = map->map[idx];
		u64 shift_cnt = sizeof(map->map[0]) * 8;

		if (!shifted) {
			v >>= bit_nr;
			shift_cnt -= bit_nr;
			shifted = 1;
		}

		while (shift_cnt) {
			if (val && (v & 0x1))
				return (s64)start_bit;
			else if ((!val) && (!(v & 0x1)))
				return (s64)start_bit;

			v >>= 1;
			shift_cnt--;
			start_bit++;
		}
	}

	return ret;
}

s64 clib_bitmap_nonzero(struct clib_bitmap *map, u64 start_bit)
{
	return clib_bitmap_find_next(map, start_bit, 1);
}

s64 clib_bitmap_zero(struct clib_bitmap *map, u64 start_bit)
{
	return clib_bitmap_find_next(map, start_bit, 0);
}
