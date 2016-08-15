/*
 * come from linux kernel list.h
 */
#ifndef __LIST_H__
#define __LIST_H__

#define offsetof(type, member) ((size_t) &((type *)0)->member)
#define container_of(ptr, type, member) ({	\
		const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
		(type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_next_entry(pos, member))

struct _list;
struct _list {
	struct _list *prev;
	struct _list *next;
};
typedef struct _list list;

#include <stdint.h>

typedef struct _list_comm {
	list list_head;
	void *st;
} list_comm;
typedef void list_comm_clean_func(void *);

#include "./error.h"
#include "./string.h"

extern void list_init(list *head);
extern void list_add(list *head, list *new);
extern void list_add_tail(list *head, list *new);
extern void list_del(list *prev, list *next);
extern void list_del_entry(list *entry);
extern void list_replace(list *old, list *new);
extern int list_is_last(list *head, list *node);
extern int list_is_empty(list *head);

extern void list_comm_init(list_comm *head);
extern int list_comm_is_empty(list_comm *head);
extern void list_comm_append(list_comm *head, list_comm *new);
extern int list_comm_new_append(list_comm *head, void *new, size_t size);
extern void list_comm_make_empty(list_comm *head,
				 list_comm_clean_func *callback);

#endif
