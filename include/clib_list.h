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
#include "../include/clib_error.h"
#include "../include/clib_linux_list.h"
#include <stdint.h>

DECL_BEGIN

struct _list_comm;
typedef struct _list_comm list_comm;
typedef struct _list_comm {
	struct list_head list_head;
	char data[0];
} list_comm;
typedef void list_comm_clean_func(void *);

extern void list_comm_init(list_comm *head);
extern int list_comm_is_empty(list_comm *head);
extern void list_comm_append(list_comm *head, list_comm *new_node);
extern int list_comm_new_append(list_comm *head, void *new_node, size_t size);
extern void list_comm_make_empty(list_comm *head,
				 list_comm_clean_func *callback);

#define	LIST_COMM_DATA(type,name,lc_var) \
type name = (type)(lc_var->data)

DECL_END

#endif /* end of include guard: LIST_H_S6RUVRAS */
