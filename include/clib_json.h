/*
 * TODO
 *
 * Copyright (C) 2020 zerons
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
#ifndef CLIB_JSON_H_MF0HJNOT
#define CLIB_JSON_H_MF0HJNOT

#include "../include/clib.h"

DECL_BEGIN

enum clib_json_valtype {
	CJVT_NONE,
	CJVT_STRING,
	CJVT_KV,
};

struct clib_json {
	struct list_head		sibling;
	struct list_head		kvs;
};

struct clib_json_kv {
	struct list_head		sibling;
	char				*key;
	union {
		struct list_head	val_head;
		char			*value;
	} value;
	int				val_type;
};

C_SYM int clib_json_test(const char *filepath);
C_SYM int clib_json_load(const char *filepath, struct list_head *head);
C_SYM int clib_json_dump(const char *filepath, struct list_head *head);
C_SYM void clib_json_cleanup(struct list_head *head);

static inline struct clib_json_kv *clib_json_kv_new(void)
{
	struct clib_json_kv *_new;
	_new = (struct clib_json_kv *)xmalloc(sizeof(*_new));
	memset(_new, 0, sizeof(*_new));
	return _new;
}

static inline void clib_json_kv_free(struct clib_json_kv *n)
{
	free(n->key);
	switch (n->val_type) {
	case CJVT_KV:
		clib_json_cleanup(&n->value.val_head);
		break;
	case CJVT_STRING:
		free(n->value.value);
		break;
	default:
		break;
	}
	free(n);
}

static inline void clib_json_iter(struct list_head *head,
				  void (*callback)(struct clib_json_kv *));
static inline void clib_json_kv_iter(struct list_head *head,
				     void (*callback)(struct clib_json_kv *))
{
	struct clib_json_kv *tmp;
	list_for_each_entry(tmp, head, sibling) {
		if (callback)
			callback(tmp);
		switch (tmp->val_type) {
		case CJVT_KV:
			clib_json_iter(&tmp->value.val_head, callback);
			break;
		case CJVT_STRING:
		default:
			break;
		}
	}
}

static inline struct clib_json *clib_json_new(void)
{
	struct clib_json *_new;
	_new = (struct clib_json *)xmalloc(sizeof(*_new));
	memset(_new, 0, sizeof(*_new));
	INIT_LIST_HEAD(&_new->kvs);
	return _new;
}

static inline void clib_json_free(struct clib_json *n)
{
	struct clib_json_kv *tmp, *next;
	list_for_each_entry_safe(tmp, next, &n->kvs, sibling) {
		list_del(&tmp->sibling);
		clib_json_kv_free(tmp);
	}
	free(n);
}

static inline void clib_json_iter(struct list_head *head,
				  void (*callback)(struct clib_json_kv *))
{
	struct clib_json *tmp;
	list_for_each_entry(tmp, head, sibling) {
		clib_json_kv_iter(&tmp->kvs, callback);
	}
}

DECL_END

#endif /* end of include guard: CLIB_JSON_H_MF0HJNOT */
