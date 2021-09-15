#include "../include/branch-logger.h"

struct branch_logger *branch_logger_alloc(u32 depth)
{
	struct branch_logger *_new;

	u32 size = depth + 1;
	size = clib_round_up(size, BRANCH_LOGGER_DEF_SIZE);

	size_t alloc_size = sizeof(_new);
	alloc_size += (size - sizeof(_new->logger));

	_new = (struct branch_logger *)malloc(alloc_size);
	if (!_new) {
		err_dbg(1, "malloc err");
		return NULL;
	}

	memset(_new, 0, alloc_size);
	_new->logger_size = size;
	_new->logger_depth = depth;

	return _new;
}

void branch_logger_free(struct branch_logger *logger)
{
	free(logger);
}

struct branch_logger *branch_logger_clone(struct branch_logger *src)
{
	struct branch_logger *_new;
	_new = branch_logger_alloc(src->logger_depth);
	if (!_new) {
		err_dbg(0, "branch_logger_alloc err");
		return NULL;
	}

	memcpy(_new->logger, src->logger, src->logger_size);
	return _new;
}

void branch_logger_copy(struct branch_logger *dst, struct branch_logger *src)
{
	if (dst->logger_size < src->logger_size) {
		err_dbg(0, "op invalid");
		return;
	}

	memcpy(dst->logger, src->logger, src->logger_size);
	return;
}

void branch_logger_set(struct branch_logger *t, u32 idx)
{
	if (idx > BRANCH_MAX) {
		err_dbg(0, "branch idx exceed, maximum %d", BRANCH_MAX);
		return;
	}

	BUG_ON(t->logger_depth >= t->logger_size);
	t->logger[t->logger_depth] = idx;
	return;
}

struct branch_logger *branch_logger_deeper(struct branch_logger *from, u32 idx)
{
	struct branch_logger *_new;
	_new = branch_logger_alloc(from->logger_depth + 1);
	if (!_new) {
		err_dbg(0, "branch_logger_alloc err");
		return NULL;
	}

	branch_logger_copy(_new, from);
	branch_logger_set(_new, idx);
	return _new;
}

u32 branch_logger_taken(struct branch_logger *t, u32 depth)
{
	if (depth > t->logger_depth) {
		err_dbg(0, "op invalid");
		return (u32)-1;
	}

	return t->logger[depth];
}
