/*
 * come from linux kernel list.h
 */
#include "../include/list.h"

void list_init(list *head)
{
	head->next = head;
	head->prev = head;
}

void list_add(list *head, list *new)
{
	new->next = head->next;
	new->prev = head;
	head->next->prev = new;
	head->next = new;
}

void list_add_tail(list *head, list *new)
{
	new->next = head;
	new->prev = head->prev;
	head->prev->next = new;
	head->prev = new;
}

void list_del(list *prev, list *next)
{
	prev->next = next;
	next->prev = prev;
}

void list_del_entry(list *entry)
{
	list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

void list_replace(list *old, list *new)
{
	new->prev = old->prev;
	new->prev->next = new;
	new->next = old->next;
	new->next->prev = new;
}

int list_is_last(list *head, list *node)
{
	return node->next == head;
}

int list_is_empty(list *head)
{
	return (head->next == head) && (head->prev == head);
}

void list_comm_init(list_comm *head)
{
	list_init(&head->list_head);
}

int list_comm_is_empty(list_comm *head)
{
	return list_is_empty(&head->list_head);
}

void list_comm_append(list_comm *head, list_comm *new)
{
	list_add_tail(&head->list_head, &new->list_head);
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
		list_del_entry(&next->list_head);
		free(next);
		next = prev;
	}
	list_comm_init(head);
}
