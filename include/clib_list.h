/*
 * come from linux kernel list.h
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

DECL_END

#endif /* end of include guard: LIST_H_S6RUVRAS */
