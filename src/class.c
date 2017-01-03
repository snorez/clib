#include "../include/class.h"

struct list_head class_list_head;

void class_init(void)
{
	INIT_LIST_HEAD(&class_list_head);

	/* some internal class init functions */
}

class_t *class_new(char *name)
{
	list_comm *next = (list_comm *)&class_list_head;
	class_t *tmp = NULL;
	list_for_each_entry(next, &next->list_head, list_head) {
		tmp = (class_t *)next->st;
		if (strcmp(tmp->name, name) == 0)
			break;
	}
	if (next == (list_comm *)&class_list_head)
		return NULL;
	class_t *new = (class_t *)malloc(sizeof(class_t));
	if (!new) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return NULL;
	}
	memcpy(new, tmp, sizeof(*tmp));
	if (new->new)
		new->data = new->new(new);
	else
		new->data = malloc(new->data_len);
	if (!new->data) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		free(new);
		return NULL;
	}
	return new;
}

int class_add(char *name, size_t size, void *ops, class_ops_new *new,
	      class_ops_free *free)
{
	class_t new_node;
	memset(&new_node, 0, sizeof(new_node));

	if (strlen(name) >= CLASS_NAME_LEN_MAX) {
		err_dbg(0, err_fmt("name too long"));
		errno = EINVAL;
		return -1;
	}

	memcpy(new_node.name, name, strlen(name));
	new_node.ops = ops;
	new_node.data_len = size;
	new_node.new = new;
	new_node.free = free;

	return list_comm_new_append((list_comm *)&class_list_head, &new,
				    sizeof(new));
}

void class_del(char *name)
{
	list_comm *next = (list_comm *)&class_list_head;
	class_t *tmp = NULL;
	list_for_each_entry(next, &next->list_head, list_head) {
		tmp = (class_t *)next->st;
		if (strcmp(tmp->name, name) == 0)
			break;
	}
	if (next == (list_comm *)&class_list_head)
		return;
	free(tmp);
	list_del(&next->list_head);
}

void class_free(class_t *obj)
{
	if (obj->free)
		obj->free(obj);
	free(obj);
}

void class_replace_ops(char *name, void *new_ops)
{
	list_comm *next = (list_comm *)&class_list_head;
	class_t *tmp = NULL;
	list_for_each_entry(next, &next->list_head, list_head) {
		tmp = (class_t *)next->st;
		if (strcmp(tmp->name, name) == 0)
			break;
	}
	if (next == (list_comm *)&class_list_head)
		return;
	tmp->ops = new_ops;
}
