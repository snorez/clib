/*
 * TODO
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

char printable[] = {' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
		'+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B',
		'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
		's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',};

char nr_en[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
		'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
		'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

int buf_printable(char *b, size_t len)
{
	size_t i = 0;
	for (i = 0; i < len; i++) {
		if (!b[i]) {
			for (; i < len; i++)
				if (b[i])
					return 0;
			break;
		}
		if (!isprint(b[i]))
			return 0;
	}
	return 1;
}

char *random_str_nr_en(size_t cnt)
{
	if ((cnt == 0) || (cnt == (size_t)-1)) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *ret = (char *)malloc(cnt+1);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, cnt+1);

	size_t len = strlen(nr_en);
	size_t i;
	for (i = 0; i < cnt; i++)
		ret[i] = nr_en[s_random()%len];
	ret[cnt] = '\0';
	return ret;
}

char *random_str(size_t cnt)
{
	if ((cnt == 0) || (cnt == (size_t)-1)) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *ret = (char *)malloc(cnt+1);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, cnt+1);

	size_t len = strlen(printable);
	size_t i;
	for (i = 0; i < cnt; i++)
		ret[i] = printable[s_random()%len];
	ret[cnt] = '\0';
	return ret;
}

char *mul_str(const char *src, size_t cnt)
{
	if (!src) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len = strlen(src);
	if ((len*cnt/len != cnt) || (len*cnt == (size_t)-1)) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *ret = (char *)malloc(len*cnt+1);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, len*cnt+1);

	size_t i;
	for (i = 0; i < len*cnt; i += len)
		memcpy(ret+i, src, len);
	ret[len*cnt] = '\0';
	return ret;
}

char *insert_str(const char *src1, const char *src2,
		     size_t pos)
{
	if (!src1 || !src2) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len1 = strlen(src1);
	size_t len2 = strlen(src2);
	size_t new_len = len1 + len2 + 1;
	if ((new_len < len1) || (new_len < len2)) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, src1, pos);
	memcpy(ret+pos, src2, len2);
	memcpy(ret+pos+len2, src1+pos, len1-pos);
	return ret;
}

char *add_str(const char *src1, const char *src2)
{
	if (!src1 || !src2) {
		err_dbg(0, "arg check error");
		return NULL;
	}
	return insert_str(src1, src2, strlen(src1));
}

char *del_str_once(const char *longer, const char *shorter)
{
	if (!longer || !shorter) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len1 = strlen(longer);
	size_t len2 = strlen(shorter);
	if (len1 <= len2) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *pos = strstr(longer, shorter);
	if (!pos) {
		err_dbg(0, "shorter not in longer");
		return NULL;
	}

	size_t new_len = len1 - len2 + 1;
	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, longer, pos-longer);
	memcpy(ret+(pos-longer), pos+len2, strlen(pos+len2));
	return ret;
}

char *del_str_all(const char *longer, const char *shorter)
{
	if (!longer || !shorter) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len1 = strlen(longer);
	size_t len2 = strlen(shorter);
	if (len1 <= len2) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *pos = strstr(longer, shorter);
	if (!pos) {
		err_dbg(0, "shorter not in longer");
		return NULL;
	}

	size_t new_len = len1 - len2 + 1;
	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, new_len);

	const char *pob = longer;
	while (pos) {
		memcpy(ret+strlen(ret), pob, pos-pob);
		pob = pos + len2;
		pos = strstr(pob, shorter);
	}
	memcpy(ret+strlen(ret), pob, strlen(pob));

	return ret;
}

char *replace_str_once(const char *src, const char *old_sub,
			   const char *new_sub)
{
	if (!src || !old_sub || !new_sub) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len1 = strlen(src);
	size_t len2 = strlen(old_sub);
	size_t len3 = strlen(new_sub);
	if (len1 <= len2) {
		err_dbg(0, "length check error");
		return NULL;
	}

	char *pos = strstr(src, old_sub);
	if (!pos) {
		err_dbg(0, "substr not in src");
		return NULL;
	}

	size_t new_len = len1 - len2 + len3 + 1;
	if ((len3 >= len2) && ((new_len < (len1-len2)) || (new_len < len3))) {
		err_dbg(0, "new length check err");
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, src, pos-src);
	memcpy(ret+(pos-src), new_sub, len3);
	memcpy(ret+(pos-src)+len3, pos+len2, strlen(pos+len2));
	return ret;
}

char *replace_str_all(const char *src, const char *old_sub,
			  const char *new_sub)
{
	if (!src || !old_sub || !new_sub) {
		err_dbg(0, "arg check error");
		return NULL;
	}

	size_t len1 = strlen(src);
	size_t len2 = strlen(old_sub);
	size_t len3 = strlen(new_sub);
	if (len1 <= len2) {
		err_dbg(0, "length check err");
		return NULL;
	}

	char *pos = strstr(src, old_sub);
	int cnt = 0;
	while (pos) {
		++cnt;
		pos = strstr(pos+len2, old_sub);
	}
	if (!cnt) {
		err_dbg(0, "substr not in src");
		return NULL;
	}

	size_t new_len = len1 + cnt * (ssize_t)(len3-len2) + 1;
	if ((len3 >= len2) && ((new_len < len1) ||
				(cnt*(len3-len2)/cnt != (len3-len2)) ||
				(new_len < cnt*(ssize_t)(len3-len2)))) {
		err_dbg(0, "new length check err");
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, "malloc error");
		return NULL;
	}
	memset(ret, 0, new_len);

	pos = strstr(src, old_sub);
	while (pos) {
		memcpy(ret+strlen(ret), src, pos-src);
		memcpy(ret+strlen(ret), new_sub, len3);
		src = pos + len2;
		pos = strstr(src, old_sub);
	}
	memcpy(ret+strlen(ret), src, strlen(src));

	return ret;
}

void dump_mem(const char *addr, size_t len)
{
	if (!addr) {
		err_dbg(0, "arg check err");
		return;
	}

	size_t i = 0;
	while (i < len) {
		fprintf(stdout, "%02x ", (unsigned)*((unsigned char *)addr+i));
		if ((i & 0x0f) == 0x0f)
			fprintf(stdout, "\n");
		i++;
	}
	if (((i-1) & 0x0f) != 0x0f)
		fprintf(stdout, "\n");
	fflush(stdout);
}

char *pattern_in_str(const char *str, const char *pattern,
		     size_t *lenth)
{
	/* TODO */
	return NULL;
}

void del_str_extra_space(char *str)
{
	if (!str) {
		err_dbg(0, "arg check err");
		return;
	}

	char *pob = str, *poe = str;
	int flag_space = 0;

	while (*poe != '\0') {
		if (isspace(*poe)) {
			if ((pob == str) || flag_space) {
				poe++;
				continue;
			}
			*pob = ' ';
			pob++;
			poe++;
			flag_space = 1;
		} else {
			if (flag_space)
				flag_space = 0;
			*pob = *poe;
			pob++;
			poe++;
		}
	}
	if (flag_space)
		*(pob-1) = '\0';
	memset(pob, 0, strlen(pob));
}

int is_empty_line(char *str)
{
	if (!str) {
		err_dbg(0, "arg check err");
		return -1;
	}

	size_t len = strlen(str);
	size_t i = 0;
	for (; i < len; i++) {
		if (!isspace(str[i]))
			return 0;
	}
	return 1;
}

static int is_word_sep(char *pos)
{
	if (!pos) {
		err_dbg(0, "arg check err");
		return -1;
	}

	/* only C, not C++. sep_2 first, then sep_1, sep_0 last*/
	char sep_0[] = {'(', ')', '[', ']', '.', '!', '~', '+', '-', '*', '&',
			'/', '%', '<', '>', '^', '|', '?', ':', '=', ',', ';',
			'#', '"', '\'', '{', '}'};
	char sep_1[] = {'-', '>', '+', '+', '-', '-', '>', '>', '<', '<',
			'<', '=', '>', '=', '=', '=', '!', '=', '&', '&',
			'|', '|', '+', '=', '-', '=', '*', '=', '/', '=',
			'&', '=', '^', '=', '|', '=', '#', '#'};
	char sep_2[] = {'<', '<', '=', '>', '>', '='};

	int i = 0;
	char *tmp = sep_2;
	for (i = 0; i < sizeof(sep_2)/3; i++) {
		if (strncmp(pos, tmp, 3) == 0)
			return 3;
		tmp += 3;
	}
	tmp = sep_1;
	for (i = 0; i < sizeof(sep_1)/2; i++) {
		if (strncmp(pos, tmp, 2) == 0)
			return 2;
		tmp += 2;
	}
	tmp = sep_0;
	for (i = 0; i < sizeof(sep_0); i++) {
		if (*pos == tmp[i])
			return 1;
	}
	return 0;
}

/*
 * UPDATE: a word contains a newline char
 * actually, get_next_word could use get_next_word_until
 */
void get_next_word(char **pos, size_t *len)
{
	*len = 0;

	if (!pos || !len || !*pos) {
		err_dbg(0, "arg check err");
		return;
	}

	char *res = *pos;
	int in_word = 0;

	while (1) {
		int c = *res;
		if (c == '\0')
			break;

		if (in_word) {
			*pos = res;
			*len = 0;

			while (isalpha(c) || isdigit(c) || (c == '_')) {
				res++;
				c = *res;
				*len += 1;
			}
			break;
		} else {
			if (isspace(c)) {
				if (c == '\n') {
					*pos = res;
					*len = 1;
					break;
				}
				res++;
			} else {
				in_word = 1;
				int ret = is_word_sep(res);
				if (ret > 0) {
					*pos = res;
					*len = ret;
					break;
				}
			}
		}
	}
}

/*
 * get next word until the `ch` show up
 */
void get_next_word_until(char **str, size_t *len, char *chs)
{
	*len = 0;

	if (!str || !len || !chs || !*str) {
		err_dbg(0, "arg check err");
		return;
	}

	char *pos = *str;
	while (isspace(*pos))
		pos++;
	*str = pos;

	while (1) {
		if (strchr(chs, *pos))
			break;
		char *pos_e;
		if ((*pos == '\'') || (*pos == '"')) {
			pos_e = get_matched_pair(pos);
			if (!pos_e) {
				err_dbg(0, "get_matched_pair err");
				*str = NULL;
				*len = 0;
				return;
			}
			*len += pos_e + 1 - pos;
			pos = pos_e + 1;
			continue;
		}
		*len += 1;
		pos++;
	}
}

static char *get_matched_quote(char *pos)
{
	int ch = *pos;
	if (unlikely((ch != '\'') && (ch != '"'))) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	pos++;
	int flag = 0;
	while (*pos) {
		if ((*pos == '\\') && (*(pos+1) == '\\')) {
			pos += 2;
			flag = 1;
			continue;
		} else if (*pos == '\\')
			flag = 0;

		if ((*pos == ch) && (*(pos-1) == '\\') && (!flag)) {
			pos++;
			continue;
		}

		if (*pos == ch)
			return pos;
		pos++;
	}

	return NULL;
}

static char *get_close_paren(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	if (unlikely(*pos != '(')) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	while (*pos) {
		if ((*pos == '\'') || (*pos == '"')) {
			pos = get_matched_quote(pos);
			if (!pos)
				return NULL;
		} else if (*pos == '(') {
			counter++;
		} else if (*pos == ')') {
			counter--;
		}

		if (!counter)
			return pos;
		pos++;
	}

	return NULL;
}

static char *get_close_braket(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	if (unlikely(*pos != '[')) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	while (*pos) {
		if ((*pos == '\'') || (*pos == '"')) {
			pos = get_matched_quote(pos);
			if (!pos)
				return NULL;
		} else if (*pos == '[') {
			counter++;
		} else if (*pos == ']') {
			counter--;
		}

		if (!counter)
			return pos;
		pos++;
	}

	return NULL;
}

static char *get_close_brace(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	if (unlikely(*pos != '{')) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	while (*pos) {
		if ((*pos == '\'') || (*pos == '"')) {
			pos = get_matched_quote(pos);
			if (!pos)
				return NULL;
		} else if (*pos == '{') {
			counter++;
		} else if (*pos == '}') {
			counter--;
		}

		if (!counter)
			return pos;
		pos++;
	}

	return NULL;
}

/*
 * get_matched_pair: get the position of the paired char
 * return NULL if something goes wrong, return start if not a paired char,
 */
char *get_matched_pair(char *start)
{
	char c = *start;
	char *ret = start;

	switch (c) {
	case '(':
		ret = get_close_paren(start);
		break;
	case '[':
		ret = get_close_braket(start);
		break;
	case '{':
		ret = get_close_brace(start);
		break;
	case '\'':
	case '"':
		ret = get_matched_quote(start);
		break;
	default:
		break;
	}
	return ret;
}

#if 0
/*
 * get_next_word: get next word start at @start
 * a word not start with seps
 * so, this function should be called by get_next_token
 */
static int get_next_word(char *start, size_t *len)
{
	char *pos = start;
	char *tmp;

	while (1) {
		if (!*pos) {
			if (pos > start)
				*len = pos-1-start;
			else
				*len = 0;
			return 0;
		}

		if ((tmp = check_tokens_in_seps(pos, def_seps, def_seps_cnt))) {
			if (pos == start) {
				*len = strlen(tmp);
				return 0;
			} else {
				*len = pos-start;
				return 0;
			}
		}

		if (isspace(*pos)) {
			*len = pos-start;
			return 0;
		}
		pos++;
	}
}

/*
 * get_next_token:
 *	not exclude space characters
 * @start: the address of the beginning of the buf
 * @len: the address of the token length
 * @use_seps: user specific separators, if true, then just check_tokens_in_seps
 * @sep_cnt: the count of the separators
 */
int get_next_token(char **start, size_t *len, char **use_seps, int sep_cnt)
{
	/*
	 * what could be a token?
	 * tokens, a word
	 * and if we meet ( [ { ' ", these could be paired, we take them all
	 * what is a token? all operators, all words,
	 * if seps is NULL, then we use ordinary operators as a seperater
	 */
	char *pos = *start;
	char *tmp_seps;
	char *orig_pos;
	*len = 0;

	while (1) {
		if (!*pos)
			return 0;

		if (!isspace(*pos))
			break;
		pos++;
		*start += 1;
	}
	pos = *start;
	orig_pos = pos;

	int specific = 1;
	if (!use_seps) {
		use_seps = def_seps;
		sep_cnt = def_seps_cnt;
		specific = 0;
	}
	if (!specific) {
		pos = get_matched_pair(orig_pos);
		if (!pos)
			return -1;
		else if (pos != orig_pos) {
			*len = pos+1-orig_pos;
			return 0;
		}
	}

	tmp_seps = check_tokens_in_seps(pos, use_seps, sep_cnt);
	if (tmp_seps) {
		*len = strlen(tmp_seps);
		return 0;
	}
	if (specific)
		return -1;

	if (specific) {
		pos = get_matched_pair(orig_pos);
		if (!pos)
			return -1;
		else if (pos != orig_pos) {
			*len = pos+1-orig_pos;
			return 0;
		}
	}

	return get_next_word(pos, len);
}
#endif

/* get_context_in get the value in `ch` . `ch`, the first char *MUST* be ch */
void get_context_in_quote(char **str, size_t *len)
{
	if (len)
		*len = 0;

	if (!str || !len || !*str) {
		err_dbg(0, "arg check err");
		return;
	}

	char *pos = *str;
	char ch = *pos;
	if ((ch != '\'') && (ch != '"')) {
		err_dbg(0, "arg check err");
		return;
	}

	*str = pos+1;
	pos = get_matched_quote(pos);
	if (pos)
		*len = pos - *str;
}

buf_struct *buf_struct_alloc(void)
{
	buf_struct *_new;
	_new = (buf_struct *)malloc(sizeof(*_new));
	if (!_new) {
		err_dbg(0, "malloc err");
		return NULL;
	}

	return _new;
}

void buf_struct_free(buf_struct *bs)
{
	free(bs->buf);
	free(bs);
}

int buf_struct_init(buf_struct *_new, char *buf, size_t len)
{
	if ((!_new) || (len == (size_t)-1) || (!len)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	memset(_new, 0, sizeof(*_new));

	_new->buf = (char *)malloc(len+1);
	if (!_new->buf) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memcpy(_new->buf, buf, len);

	_new->buf[len] = 0;
	_new->buf_len = len+1;

	return 0;
}

int buf_struct_new_append(struct list_head *head, char *buf, size_t len)
{
	if (!head || !buf || (len == (size_t)-1)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	buf_struct bs;
	if (buf_struct_init(&bs, buf, len)) {
		err_dbg(0, "buf_struct_init err");
		return -1;
	}

	return list_comm_new_append(head, &bs, sizeof(bs));
}

static int buf_struct_cleanup(void *data)
{
	buf_struct *bs = data;
	if (!bs)
		return 0;
	free(bs->buf);
	bs->buf = NULL;
	return 0;
}

void buf_struct_list_cleanup(struct list_head *head)
{
	list_comm_cleanup(head, buf_struct_cleanup);
}

int buf_struct_merge(buf_struct *bbs, buf_struct *ebs)
{
	if ((!bbs) || (!ebs)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	size_t len = (bbs->buf_len-1) + ebs->buf_len;
	if ((len <= (bbs->buf_len-1)) || (len <= ebs->buf_len)) {
		err_dbg(0, "length check err");
		return -1;
	}

	char *tmp = malloc(len);
	if (!tmp) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memcpy(tmp, bbs->buf, bbs->buf_len-1);
	memcpy(tmp+bbs->buf_len-1, ebs->buf, ebs->buf_len);

	free(bbs->buf);
	bbs->buf = tmp;
	bbs->buf_len = len;

	free(ebs->buf);
	ebs->buf = NULL;
	ebs->buf_len = 0;
	return 0;
}

int buf_struct_print(void *data)
{
	buf_struct *bs = data;
	if (buf_printable(bs->buf, bs->buf_len))
		fprintf(stdout, "%s\n", bs->buf);
	else
		dump_mem(bs->buf, bs->buf_len-1);
	fflush(stdout);
	return 0;
}

/*
 * dict key name, valid char exclude '' "" : , { }
 */
static void get_dict_key(char **str, size_t *len, char *sep)
{
	*len = 0;

	if (!str || !len || !sep || !*str) {
		err_dbg(0, "arg check err");
		return;
	}

	char *pos = *str;

	while ((*pos != *sep) && isspace(*pos))
		pos++;

	if ((*pos == '\'') || (*pos == '"')) {
		get_context_in_quote(&pos, len);
		*str = pos;
		return;
	} else {
		get_next_word_until(&pos, len, sep);
		*str = pos;
		return;
	}
}

/*
 * the first char *MUST* be the sep `:`
 */
static void get_dict_value(char **str, size_t *len, char *sep)
{
	*len = 0;

	if (!str || !len || !sep || !*str) {
		err_dbg(0, "arg check err");
		return;
	}

	char *pos = *str;
	if (!strchr(sep, *pos))
		return;
	pos++;

	while (isspace(*pos))
		pos++;

	if ((*pos == '\'') || (*pos == '"')) {
		get_context_in_quote(&pos, len);
		*str = pos;
		return;
	} else {
		get_next_word_until(&pos, len, "\n,}");
		*str = pos;
		return;
	}
}

/*
 * the input `str` should like this:
 * {"vhost": "1.1.1.1", "host": "2.2.22.2"}
 * or
 * {
 *	xxx: yyy
 *	aaa: bbb
 * }
 * the whole dict is around a pair of '{' '}'
 * the returned value is a list_dt structure,
 * it's like head<->key<->value<->key<->value<->...<->key<->value<->head
 * `sep` means the charactor between KEY and VALUE, like `:` `=`
 */
int get_dict_key_value(struct list_head *head, char *str, char *sep)
{
	if (!head || !str || !sep) {
		err_dbg(0, "arg check err");
		return -1;
	}

	char *pos = str;
	size_t len = 0;
	int cnt_dicts = 0;
	int err;

	/* that is the beginning of the dict */
	int flag_value = 0;
	while (*pos != '\0') {
		if (isspace(*pos)) {
			pos++;
			continue;
		}

		if (*pos == '}')
			cnt_dicts--;
		if ((*pos == '}') && (!cnt_dicts))
			break;
		if (*pos == '}') {
			pos++;
			continue;
		}

		if (*pos == '{') {
			cnt_dicts++;
			pos++;
			continue;
		}

		if (*pos == *sep) {
			flag_value = 1;
			get_dict_value(&pos, &len, sep);
		} else {
			flag_value = 0;
			get_dict_key(&pos, &len, sep);
		}

		if (!len) {
			err_dbg(0, "key/value parse error");
			break;
		}

		err = buf_struct_new_append(head, pos, len);
		if (err == -1) {
			err_dbg(0, "buf_struct_new_append err");
			buf_struct_list_cleanup(head);
			return -1;
		}
		pos += len;
		char *potmp = pos;
		if (flag_value) {
			potmp = strchr(pos, ',');
			if (!potmp)
				potmp = strchr(pos, '\n');
			if (!potmp)
				potmp = strchr(pos, '}');
		} else {
			potmp = strstr(pos, sep);
		}
		if (!potmp)
			break;
		if (strchr("\n,}", *potmp))
			potmp++;
		pos = potmp;
	}
	return 0;
}

int str_split(struct list_head *head, const char *src, const char *key)
{
	if (!head || !src || !key || (strlen(src) == (size_t)-1)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	INIT_LIST_HEAD(head);
	size_t len = strlen(src) + 1;
	char *src_tmp = (char *)malloc(len);
	if (!src_tmp) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memset(src_tmp, 0, len);
	memcpy(src_tmp, src, len);

	char *pob = src_tmp, *poe = NULL;
	int err;
	poe = strstr(pob, key);
	while (poe) {
		*poe = '\0';
		if (poe > pob) {
			err = buf_struct_new_append(head,pob,strlen(pob));
			if (err) {
				err_dbg(0, "buf_struct_new_append err");
				buf_struct_list_cleanup(head);
				free(src_tmp);
				return -1;
			}
		}
		pob = poe + strlen(key);
		poe = strstr(pob, key);
	}

	/* the last one */
	err = 0;
	if (*pob != '\0')
		err = buf_struct_new_append(head,pob,strlen(pob));
	if (err) {
		err_dbg(0, "buf_struct_new_append err");
		buf_struct_list_cleanup(head);
		free(src_tmp);
		return -1;
	}

	free(src_tmp);
	return 0;
}
