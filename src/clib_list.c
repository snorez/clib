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

int list_comm_new_append(struct list_head *head, void *new, size_t size)
{
	list_comm *new_node = (list_comm *)malloc(sizeof(list_comm) + size);
	if (!new_node) {
		err_dbg(0, "malloc err");
		return -1;
	}

	memcpy(new_node->data, new, size);
	list_add_tail(&new_node->list_head, head);
	return 0;
}

void list_comm_cleanup(struct list_head *head, list_comm_callback *callback)
{
	list_comm *cur, *next;
	list_for_each_entry_safe(cur, next, head, list_head) {
		if (callback)
			callback((void *)cur->data);
		list_del(&cur->list_head);
		free(cur);
	}
	INIT_LIST_HEAD(head);
}

int list_comm_iter(struct list_head *head, list_comm_callback *cb)
{
	int err;
	list_comm *cur, *next;
	list_for_each_entry_safe(cur, next, head, list_head) {
		err = cb((void *)cur->data);
		if (err)
			return -1;
	}
	return 0;
}
