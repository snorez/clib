/*
 * TODO
 *
 * Copyright (C) 2021 zerons
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef BRANCH_LOGGER_H_1O6KNJXE
#define BRANCH_LOGGER_H_1O6KNJXE

#include "../include/clib.h"

DECL_BEGIN

/* how deeper can the path goes */
#define	BRANCH_LOGGER_DEF_SIZE	8
#define	BRANCH_MAX		255

/* NOTE: maximum branches for one node we can handle is 255. */
struct branch_logger {
	u32		logger_size;
	u32		logger_depth;

	/* this branch idx can be found at the logger[logger_depth] */
	u8		logger[BRANCH_LOGGER_DEF_SIZE];
};

extern struct branch_logger *branch_logger_alloc(u32 depth);
extern void branch_logger_free(struct branch_logger *logger);
extern struct branch_logger *branch_logger_clone(struct branch_logger *src);
extern void branch_logger_copy(struct branch_logger *dst, struct branch_logger *src);
extern void branch_logger_set(struct branch_logger *t, u32 idx);
extern struct branch_logger *branch_logger_deeper(struct branch_logger *from, u32 idx);
extern u32 branch_logger_taken(struct branch_logger *t, u32 depth);

DECL_END

#endif /* end of include guard: BRANCH_LOGGER_H_1O6KNJXE */
