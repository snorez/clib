#include "../include/clib_mm.h"

static LIST_HEAD(clib_mm_head);
static lock_t mm_head_lock;

static struct clib_mm *clib_mm_find(char *desc)
{
	struct clib_mm *t;
	list_for_each_entry(t, &clib_mm_head, sibling) {
		if (!strcmp(t->desc, desc)) {
			atomic_inc(&t->refcount);
			return t;
		}
	}
	return NULL;
}

static int clib_mm_init(struct clib_mm *t, int fd, unsigned long start, size_t len,
			int expandable)
{
	unsigned long mmap_addr = clib_round_down(start, PAGE_SIZE);
	size_t real_len = clib_round_up(start+len, PAGE_SIZE) - mmap_addr;
	size_t mmap_len = real_len;
	if (mmap_len > CLIB_MM_MMAP_BLKSZ)
		mmap_len = CLIB_MM_MMAP_BLKSZ;
	char *addr = mmap((void *)mmap_addr, mmap_len,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_FIXED | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED) {
		err_dbg(1, err_fmt("mmap err"));
		return -1;
	}

	t->fd = fd;
	t->mm_start = mmap_addr;
	t->mm_head = start;
	t->mm_cur = t->mm_head;
	t->mm_tail = t->mm_start + mmap_len;
	t->mm_end = t->mm_start + real_len;
	t->expandable = !!expandable;
	return 0;
}

static int clib_mm_dump(struct clib_mm *t)
{
	if (t->fd < 0)
		return 0;
	int err = write(t->fd, (char *)t->mm_head, t->mm_cur - t->mm_head);
	if (err == -1) {
		err_dbg(1, err_fmt("write err"));
		return -1;
	}

	return 0;
}

static int clib_mm_expand(struct clib_mm *t, size_t size_need)
{
	if ((t->mm_tail - t->mm_cur) >= size_need)
		return 0;

	int err = 0;
	unsigned long mmap_addr;
	size_t mmap_len;
	if ((t->mm_end - t->mm_cur) >= size_need) {
		/* INFO, need map larger area */
		mmap_len = size_need - (t->mm_tail - t->mm_cur);
		mmap_len = clib_round_up(mmap_len, PAGE_SIZE);
		mmap_addr = t->mm_tail;
		char *addr = mmap((void *)mmap_addr, mmap_len,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_FIXED | MAP_SHARED, -1, 0);
		if (addr == MAP_FAILED) {
			err_dbg(1, err_fmt("mmap err"));
			return -1;
		}
		t->mm_tail += mmap_len;
		return 0;
	} else {
		if (!t->expandable) {
			err_dbg(0, err_fmt("not expandable, no enough room"));
			return -1;
		}

		/* INFO, need to munmap current area, remap the next area */
		if (size_need > (t->mm_end - t->mm_start)) {
			err_dbg(0, err_fmt("request size too large"));
			return -1;
		}

		err = clib_mm_dump(t);
		if (err == -1) {
			err_dbg(0, err_fmt("clib_mm_dump err"));
			return -1;
		}

		err = munmap((void *)t->mm_start, t->mm_tail - t->mm_start);
		if (err == -1) {
			err_dbg(0, err_fmt("munmap err"));
			return -1;
		}

		err = clib_mm_init(t, t->fd, t->mm_end, t->mm_end-t->mm_start,
					t->expandable);
		if (err) {
			err_dbg(0, err_fmt("clib_mm_init err"));
			list_del(&t->sibling);
			memset(t, 0, sizeof(*t));
			free(t);
			return -1;
		}

		err = clib_mm_expand(t, size_need);
		if (err) {
			err_dbg(0, err_fmt("clib_mm_expand err"));
			return -1;
		}

		return 0;
	}
}

static void clib_mm_put(struct clib_mm *t)
{
	if (atomic_dec_and_test(&t->refcount)) {
		list_del(&t->sibling);
		free(t);
	}
}

int clib_mm_setup(char *desc, int fd, unsigned long start, size_t len, int expandable)
{
	if (unlikely(strlen(desc) >= CLIB_MM_DESC_LEN)) {
		err_dbg(0, err_fmt("desc too long"));
		return -1;
	}
	if (unlikely((start + len) <= start)) {
		err_dbg(0, err_fmt("len invalid"));
		return -1;
	}

	int err = 0;
	mutex_lock(&mm_head_lock);
	struct clib_mm *t = clib_mm_find(desc);
	if (t) {
		clib_mm_put(t);
		err_dbg(0, err_fmt("clib_mm desc exists"));
		mutex_unlock(&mm_head_lock);
		return -1;
	}

	t = (struct clib_mm *)malloc(sizeof(*t));
	if (!t) {
		err_dbg(0, err_fmt("malloc err"));
		mutex_unlock(&mm_head_lock);
		return -1;
	}
	memset(t, 0, sizeof(*t));

	memcpy(t->desc, desc, strlen(desc));
	err = clib_mm_init(t, fd, start, len, expandable);
	if (err) {
		err_dbg(0, err_fmt("clib_mm_init err"));
		err = -1;
		mutex_unlock(&mm_head_lock);
		goto err_free;
	}
	atomic_set(&t->refcount, 1);
	list_add_tail(&t->sibling, &clib_mm_head);
	mutex_unlock(&mm_head_lock);
	return 0;

err_free:
	free(t);
	return err;
}

int clib_mm_cleanup(char *desc)
{
	int err = 0;
	mutex_lock(&mm_head_lock);
	struct clib_mm *t = clib_mm_find(desc);
	if (!t) {
		err_dbg(0, err_fmt("clib_mm desc not found"));
		mutex_unlock(&mm_head_lock);
		return -1;
	}

	err = clib_mm_dump(t);
	if (err == -1) {
		err_dbg(0, err_fmt("clib_mm_dump err"));
		mutex_unlock(&mm_head_lock);
		return -1;
	}

	err = munmap((void *)t->mm_start, t->mm_tail - t->mm_start);
	if (err == -1) {
		err_dbg(1, err_fmt("munmap err"));
		mutex_unlock(&mm_head_lock);
		return -1;
	}

	clib_mm_put(t);
	clib_mm_put(t);
	mutex_unlock(&mm_head_lock);
	return 0;
}

unsigned long clib_mm_get(char *desc, size_t len)
{
	int err = 0;
	mutex_lock(&mm_head_lock);
	struct clib_mm *t = clib_mm_find(desc);
	if (!t) {
		err_dbg(0, err_fmt("clib_mm desc not found"));
		mutex_unlock(&mm_head_lock);
		return 0;
	}

	err = clib_mm_expand(t, len);
	if (err) {
		err_dbg(0, err_fmt("clib_mm_expand err"));
		clib_mm_put(t);
		mutex_unlock(&mm_head_lock);
		return 0;
	}

	unsigned long ret = t->mm_cur;
	t->mm_cur += len;
	clib_mm_put(t);
	mutex_unlock(&mm_head_lock);
	return ret;
}
