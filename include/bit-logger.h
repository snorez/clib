#ifndef BIT_LOGGER_H_B2CHTGFQ
#define BIT_LOGGER_H_B2CHTGFQ

#include "clib.h"

DECL_BEGIN

struct bit_logger {
	struct list_head	sibling;
	uint64_t		start_pos;
	uint64_t		bits;
};

C_SYM int bit_log_add(struct list_head *head, uint64_t pos);
C_SYM void bit_log_cleanup(struct list_head *head);

DECL_END

#endif /* end of include guard: BIT_LOGGER_H_B2CHTGFQ */
