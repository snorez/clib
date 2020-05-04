/*
 * TODO
 * Copyright (C) 2018  zerons
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
#ifndef LIST_H_S6RUVRAS
#define LIST_H_S6RUVRAS


#include "../include/clib_utils.h"
#include "../include/clib_eh.h"
#include "../include/clib_linux_list.h"
#include <stdint.h>

DECL_BEGIN

typedef struct {
	struct list_head	list_head;
	char			data[0];
} list_comm;
typedef int list_comm_callback(void *);

extern int list_comm_new_append(struct list_head *head, void *new_node, size_t size);
extern void list_comm_cleanup(struct list_head *head, list_comm_callback *callback);
extern int list_comm_iter(struct list_head *head, list_comm_callback *callback);

#define	LIST_COMM_DATA_TO_VAR(type,name,lc_var) \
type name = (type)(lc_var->data)

DECL_END

#endif /* end of include guard: LIST_H_S6RUVRAS */
