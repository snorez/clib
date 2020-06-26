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
#include "../include/clib_json.h"

static int adjust_json_buf(char **buf, size_t total_len, size_t *this_len)
{
	int ret = 0;
	char *start = *buf;
	char *end = start + total_len;

	while (start < end) {
		if ((*start == '[') || (*start == '{'))
			break;
		if (isspace(*start))
			start++;
		else
			return -1;
	}

	if (start == end)
		return -1;

	char *matched_sym = get_matched_pair(start);
	if (!matched_sym)
		return -1;

	*buf = start;
	*this_len = matched_sym + 1 - start;
	return 0;
}

/*
 * clib_json_test: check the JSON file format
 */
int clib_json_test(const char *filepath)
{
	struct list_head head;
	int ret;

	INIT_LIST_HEAD(&head);
	ret = clib_json_load(filepath, &head);
	if (ret) {
		clib_json_cleanup(&head);
		return -1;
	}

	clib_json_cleanup(&head);
	return 0;
}

static int clib_json_buf_load(char *buf, size_t len, struct list_head *head)
{
	int ret;
	char *start, *end;
	size_t this_len;

	start = buf;
	ret = adjust_json_buf(&start, len, &this_len);
	if (ret) {
		err_dbg(0, "adjust_json_buf err");
		return -1;
	}
	end = start + this_len;

	struct clib_json *cur_cj = NULL;
	while (start < end) {
		if (isspace(*start) || (*start == '[') || (*start == ']') ||
				(*start == '}') || (*start == ',')) {
			start++;
			continue;
		} else if ((*start != '{') && (*start != '"')) {
			err_dbg(0, "format err, %x", *start);
			return -1;
		}

		if (*start == '{') {
			cur_cj = clib_json_new();
			list_add_tail(&cur_cj->sibling, head);
		}

		char *key_start = start;
		if (*key_start == '{')
			key_start++;
		char *key_end = NULL;
		while (key_start < end) {
			if (isspace(*key_start)) {
				key_start++;
				continue;
			} else if (*key_start != '"') {
				err_dbg(0, "format err: %x", *key_start);
				return -1;
			}
			break;
		}
		if (key_start == end) {
			err_dbg(0, "format err");
			return -1;
		}
		key_end = get_matched_pair(key_start);
		if (!key_end) {
			err_dbg(0, "format err");
			return -1;
		}

		struct clib_json_kv *new_kv;
		new_kv = clib_json_kv_new();
		new_kv->key = (char *)malloc(key_end - key_start);
		memset(new_kv->key, 0, key_end - key_start);
		memcpy(new_kv->key, key_start+1, key_end-(key_start+1));

		char *sep = key_end + 1;
		while (sep < end) {
			if (isspace(*sep)) {
				sep++;
				continue;
			} else if (*sep != ':') {
				err_dbg(0, "format err: %x", *sep);
				return -1;
			}
			break;
		}
		if (sep == end) {
			err_dbg(0, "format err");
			return -1;
		}

		char *val_start = sep + 1;
		char *val_end = NULL;
		while (val_start < end) {
			if ((*val_start == '[') || (*val_start == '{')) {
				new_kv->val_type = CJVT_KV;
				INIT_LIST_HEAD(&new_kv->value.val_head);
				size_t subkv_len;
				ret = adjust_json_buf(&val_start,
							end-val_start,
							&subkv_len);
				if (ret) {
					err_dbg(0, "adjust_json_buf err");
					return -1;
				}

				ret = clib_json_buf_load(val_start,subkv_len,
						&new_kv->value.val_head);
				if (ret) {
					err_dbg(0, "clib_json_buf_load err");
					return -1;
				}
				val_end = val_start + subkv_len;
				break;
			} else if (*val_start == '"') {
				new_kv->val_type = CJVT_STRING;
				val_end = get_matched_pair(val_start);
				char *v;
				v = (char *)malloc(val_end - val_start);
				memset(v, 0, val_end - val_start);
				memcpy(v,val_start+1,val_end-(val_start+1));
				new_kv->value.value = v;
				val_end += 1;
				break;
			} else if (isspace(*val_start)) {
				val_start++;
				continue;
			} else {
				err_dbg(0, "format err: %x", *val_start);
				return -1;
			}
		}
		if (val_start == end) {
			err_dbg(0, "format err");
			return -1;
		}

		list_add_tail(&new_kv->sibling, &cur_cj->kvs);
		start = val_end;
	}

	return 0;
}

int clib_json_load(const char *filepath, struct list_head *head)
{
	int ret;
	size_t flen;
	char *fctx;

	fctx = clib_loadfile(filepath, &flen);
	if (!fctx) {
		err_dbg(0, "clib_loadfile err");
		return -1;
	}

	ret = clib_json_buf_load(fctx, flen, head);
	free(fctx);

	return ret;
}

int clib_json_dump(const char *filepath, struct list_head *head)
{
	/* TODO */
	return 0;
}

void clib_json_cleanup(struct list_head *head)
{
	struct clib_json *tmp, *next;
	list_for_each_entry_safe(tmp, next, head, sibling) {
		list_del(&tmp->sibling);
		clib_json_free(tmp);
	}
}
