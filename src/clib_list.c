/*
 * come from linux kernel list.h
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
#include "../include/clib.h"

void list_comm_init(list_comm *head)
{
	INIT_LIST_HEAD(&head->list_head);
}

int list_comm_is_empty(list_comm *head)
{
	return list_empty(&head->list_head);
}

void list_comm_append(list_comm *head, list_comm *new)
{
	list_add_tail(&new->list_head, &head->list_head);
}

int list_comm_new_append(list_comm *head, void *new, size_t size)
{
	list_comm *new_node = (list_comm *)malloc(sizeof(list_comm) + size);
	if (!new_node) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}

	memcpy(new_node->data, new, size);
	list_comm_append(head, new_node);
	return 0;
}

void list_comm_make_empty(list_comm *head,
			  list_comm_clean_func *callback)
{
	list_comm *prev = head, *next = head;
	list_for_each_entry(next, &head->list_head, list_head) {
		if (callback)
			callback((void *)next->data);
		prev = (list_comm *)next->list_head.prev;
		list_del(&next->list_head);
		free(next);
		next = prev;
	}
	list_comm_init(head);
}
