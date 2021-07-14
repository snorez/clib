#include "../include/bit-logger.h"

static struct bit_logger *bit_logger_alloc(void)
{
	struct bit_logger *ret;

	ret = (struct bit_logger *)malloc(sizeof(*ret));
	if (!ret) {
		err_dbg(1, "malloc err");
		return NULL;
	}

	memset(ret, 0, sizeof(*ret));
	return ret;
}

static void bit_logger_free(struct bit_logger *log)
{
	free(log);
}

static struct bit_logger *bit_logger_new(uint64_t pos)
{
	struct bit_logger *ret;

	ret = bit_logger_alloc();
	if (!ret) {
		err_dbg(0, "bit_logger_alloc err");
		return NULL;
	}

	ret->start_pos = pos;
	ret->bits = 1;
	return ret;
}

int bit_log_add(struct list_head *head, uint64_t pos)
{
	struct bit_logger *tmp;
	list_for_each_entry(tmp, head, sibling) {
		uint64_t pos_b = tmp->start_pos;
		uint64_t pos_e = pos_b + tmp->bits;

		if (pos == pos_e) {
			tmp->bits += 1;
			return 0;
		} else if (pos == (pos_b - 1)) {
			tmp->start_pos -= 1;
			tmp->bits += 1;
			return 0;
		} else if ((pos >= pos_b) && (pos < pos_e)) {
			return 0;
		}
	}

	struct bit_logger *new_log;
	new_log = bit_logger_new(pos);
	if (!new_log) {
		err_dbg(0, "bit_logger_new err");
		return -1;
	}

	list_add_tail(&new_log->sibling, head);

	return 0;
}

void bit_log_cleanup(struct list_head *head)
{
	struct bit_logger *tmp, *next;
	list_for_each_entry_safe(tmp, next, head, sibling) {
		list_del(&tmp->sibling);
		bit_logger_free(tmp);
	}
}
