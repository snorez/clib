#ifndef CLASS_H
#define CLASS_H

#include "./list.h"

#define CLASS_NAME_LEN_MAX 16
struct _class_t;
typedef void *(class_ops_new)(struct _class_t *);
typedef void (class_ops_free)(struct _class_t *);

typedef struct _class_t {
	char name[CLASS_NAME_LEN_MAX];
	class_ops_new *new;
	class_ops_free *free;
	size_t data_len;
	void *data; /* this is private */
	void *ops; /* this is shared with other objects */
} class_t;

extern list class_list_head;

extern void class_init(void);
extern class_t *class_new(char *name);
extern int class_add(char *name, size_t size, void *ops, class_ops_new *new,
		     class_ops_free *free);
extern void class_del(char *name);
extern void class_free(class_t *obj);
extern void class_replace_ops(char *name, void *new_ops);

#endif
