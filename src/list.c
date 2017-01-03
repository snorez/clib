/*
 * come from linux kernel list.h
 */
#include "../include/list.h"

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
	list_comm *new_node = (list_comm *)malloc(sizeof(list_comm));
	if (!new_node) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}

	if (size) {
		void *new_st = malloc(size);
		if (!new_st) {
			err_dbg(0, err_fmt("malloc err"));
			errno = ENOMEM;
			free(new_node);
			return -1;
		}
		memcpy(new_st, new, size);
		new_node->st = new_st;
	} else
		new_node->st = new;
	list_comm_append(head, new_node);
	return 0;
}

void list_comm_make_empty(list_comm *head,
			  list_comm_clean_func *callback)
{
	list_comm *prev = head, *next = head;
	list_for_each_entry(next, &head->list_head, list_head) {
		if (callback)
			callback((void *)next->st);
		prev = (list_comm *)next->list_head.prev;
		list_del(&next->list_head);
		free(next);
		next = prev;
	}
	list_comm_init(head);
}
