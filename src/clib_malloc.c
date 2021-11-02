/*
 * TODO
 * Copyright (C) 2021  zerons
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

int clib_inner_slow_heap;
#if 0
static int clib_audit_heap;
static rwlock_t clib_malloc_lock;
static SLIST_HEAD(clib_malloc_head);

static struct clib_heap_audit_node *clib_heap_audit_node_alloc(void)
{
	struct clib_heap_audit_node *_new;
	_new = (struct clib_heap_audit_node *)CLIB_INNER_MALLOC(sizeof(*_new));
	memset(_new, 0, sizeof(*_new));
	return _new;
}

static struct clib_heap_audit_node *clib_heap_audit_node_find(void *ptr)
{
	struct clib_heap_audit_node *tmp;
	slist_for_each_entry(tmp, &clib_malloc_head, sibling) {
		if (tmp->ptr == ptr)
			return tmp;
	}

	return NULL;
}

void *clib_heap_audit_alloc(size_t len)
{
	void *ptr = CLIB_INNER_MALLOC(len);
	BUG_ON(!ptr);

	write_lock(&clib_malloc_lock);
	if (unlikely(clib_audit_heap)) {
		struct clib_heap_audit_node *newnode = clib_heap_audit_node_alloc();
		newnode->ptr = ptr;
		newnode->alloc_len = len;


		BUG_ON(clib_heap_audit_node_find(newnode->ptr));
		slist_add(&newnode->sibling, &clib_malloc_head);
	}
	write_unlock(&clib_malloc_lock);

	return ptr;
}

void *clib_heap_audit_realloc(void *ptr, size_t len)
{
	void *ret = CLIB_INNER_REALLOC(ptr, len);
	BUG_ON(!ret);

	write_lock(&clib_malloc_lock);
	if (unlikely(clib_audit_heap)) {
		struct clib_heap_audit_node *node;

		node = clib_heap_audit_node_find(ptr);
		if (node) {
			node->ptr = ret;
			node->alloc_len = len;
		}
	}
	write_unlock(&clib_malloc_lock);

	return ret;
}

void clib_heap_audit_free(void *ptr)
{
	write_lock(&clib_malloc_lock);
	if (unlikely(clib_audit_heap)) {

		struct clib_heap_audit_node *node;
		node = clib_heap_audit_node_find(ptr);

		if (node) {
			slist_del(&node->sibling, &clib_malloc_head);
		}

		CLIB_INNER_FREE(node);
	}
	write_unlock(&clib_malloc_lock);

	CLIB_INNER_FREE(ptr);
}

void *clib_heap_audit(void *ptr, ssize_t offset, size_t rlen, char *file, int line)
{
	void *ret = ptr + offset;

	read_lock(&clib_malloc_lock);
	if (unlikely(clib_audit_heap)) {
		void *ptr_b = ptr + offset;
		void *ptr_e = ptr + offset + rlen;

		struct clib_heap_audit_node *node;
		node = clib_heap_audit_node_find(ptr);

		if (node) {
			if ((ptr_b >= node->ptr) &&
			    (ptr_e <= (node->ptr + node->alloc_len))) {
				ret = ptr + offset;
			} else {
				BUG_MSG("HEAP CORRUPT in %s %d.", file, line);
			}
		}
	}
	read_unlock(&clib_malloc_lock);

	return ret;
}

void clib_heap_audit_enable(void)
{
	write_lock(&clib_malloc_lock);

	clib_audit_heap = 1;

	write_unlock(&clib_malloc_lock);
}

void clib_heap_audit_disable(void)
{
	write_lock(&clib_malloc_lock);

	clib_audit_heap = 0;

	struct clib_heap_audit_node *tmp;
	slist_for_each_entry(tmp, &clib_malloc_head, sibling) {
		slist_del(&tmp->sibling, &clib_malloc_head);
		CLIB_INNER_FREE(tmp);
	}

	write_unlock(&clib_malloc_lock);
}
#endif
