#include "../include/clib_string.h"

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

/*
 * random seed use current systime may not be safe, so
 * libsodium may be a good choice, use randombytes_buf/randombytes_uniform
 * instead
 */
long s_random(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		err_dbg(1, err_fmt("gettimeofday err"));
		return -1;
	}
	srand(tv.tv_sec + tv.tv_usec);
	return random();
}

char *random_str_nr_en_fau(size_t cnt)
{
	if ((cnt == 0) || (cnt == -1ULL)) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(cnt+1);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, cnt+1);

	size_t len = strlen(nr_en);
	size_t i;
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		err_dbg(1, err_fmt("gettimeofday error"));
		free(ret);
		return NULL;
	}
	srand(tv.tv_sec + tv.tv_usec);
	for (i = 0; i < cnt; i++)
		ret[i] = nr_en[random()%len];
	ret[cnt] = '\0';
	return ret;
}

char *random_str_fau(size_t cnt)
{
	if ((cnt == 0) || (cnt == -1ULL)) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(cnt+1);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, cnt+1);

	size_t len = strlen(printable);
	size_t i;
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		err_dbg(1, err_fmt("gettimeofday error"));
		free(ret);
		return NULL;
	}
	srand(tv.tv_sec + tv.tv_usec);
	for (i = 0; i < cnt; i++)
		ret[i] = printable[random()%len];
	ret[cnt] = '\0';
	return ret;
}

char *mul_str_fau(const char *src, size_t cnt)
{
	if (!src) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len = strlen(src);
	if ((len*cnt/len != cnt) || (len*cnt == -1ULL)) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(len*cnt+1);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, len*cnt+1);

	size_t i;
	for (i = 0; i < len*cnt; i += len)
		memcpy(ret+i, src, len);
	ret[len*cnt] = '\0';
	return ret;
}

char *insert_str_fau(const char *src1, const char *src2,
		     size_t pos)
{
	if (!src1 || !src2) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len1 = strlen(src1);
	size_t len2 = strlen(src2);
	size_t new_len = len1 + len2 + 1;
	if ((new_len < len1) || (new_len < len2)) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, src1, pos);
	memcpy(ret+pos, src2, len2);
	memcpy(ret+pos+len2, src1+pos, len1-pos);
	return ret;
}

char *add_str_fau(const char *src1, const char *src2)
{
	if (!src1 || !src2) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}
	return insert_str_fau(src1, src2, strlen(src1));
}

char *del_str_once_fau(const char *longer, const char *shorter)
{
	if (!longer || !shorter) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len1 = strlen(longer);
	size_t len2 = strlen(shorter);
	if (len1 < len2) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *pos = strstr(longer, shorter);
	if (!pos) {
		err_dbg(0, err_fmt("shorter not in longer"));
		errno = EINVAL;
		return NULL;
	}

	size_t new_len = len1 - len2 + 1;
	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, longer, pos-longer);
	memcpy(ret+(pos-longer), pos+len2, strlen(pos+len2));
	return ret;
}

char *del_str_all_fau(const char *longer, const char *shorter)
{
	if (!longer || !shorter) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len1 = strlen(longer);
	size_t len2 = strlen(shorter);
	if (len1 < len2) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *pos = strstr(longer, shorter);
	if (!pos) {
		err_dbg(0, err_fmt("shorter not in longer"));
		errno = EINVAL;
		return NULL;
	}

	size_t new_len = len1 - len2 + 1;
	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
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

char *replace_str_once_fau(const char *src, const char *old_sub,
			   const char *new_sub)
{
	if (!src || !old_sub || !new_sub) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len1 = strlen(src);
	size_t len2 = strlen(old_sub);
	size_t len3 = strlen(new_sub);
	if (len1 < len2) {
		err_dbg(0, err_fmt("lenth check error"));
		errno = EINVAL;
		return NULL;
	}

	char *pos = strstr(src, old_sub);
	if (!pos) {
		err_dbg(0, err_fmt("substr not in src"));
		errno = EINVAL;
		return NULL;
	}

	size_t new_len = len1 - len2 + len3 + 1;
	if ((len3 >= len2) && ((new_len < (len1-len2)) || (new_len < len3))) {
		err_dbg(0, err_fmt("new lenth check err"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, new_len);

	memcpy(ret, src, pos-src);
	memcpy(ret+(pos-src), new_sub, len3);
	memcpy(ret+(pos-src)+len3, pos+len2, strlen(pos+len2));
	return ret;
}

char *replace_str_all_fau(const char *src, const char *old_sub,
			  const char *new_sub)
{
	if (!src || !old_sub || !new_sub) {
		err_dbg(0, err_fmt("arg check error"));
		errno = EINVAL;
		return NULL;
	}

	size_t len1 = strlen(src);
	size_t len2 = strlen(old_sub);
	size_t len3 = strlen(new_sub);
	if (len1 < len2) {
		err_dbg(0, err_fmt("lenth check err"));
		errno = EINVAL;
		return NULL;
	}

	char *pos = strstr(src, old_sub);
	int cnt = 0;
	while (pos) {
		++cnt;
		pos = strstr(pos+len2, old_sub);
	}
	if (!cnt) {
		err_dbg(0, err_fmt("substr not in src"));
		errno = EINVAL;
		return NULL;
	}

	size_t new_len = len1 + cnt * (ssize_t)(len3-len2) + 1;
	if ((len3 >= len2) && ((new_len < len1) ||
			       (new_len < cnt*(ssize_t)(len3-len2)))) {
		err_dbg(0, err_fmt("new lenth check err"));
		errno = EINVAL;
		return NULL;
	}

	char *ret = (char *)malloc(new_len);
	if (!ret) {
		err_dbg(0, err_fmt("malloc error"));
		errno = ENOMEM;
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
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
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
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
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
			*pob = *poe;
			pob++;
			poe++;
			flag_space = 1;
			continue;
		} else {
			if (flag_space) {
				flag_space = 0;
			}
			*pob = *poe;
			pob++;
			poe++;
			continue;
		}
	}
	memset(pob, 0, strlen(pob));
}

int is_empty_line(char *str)
{
	if (!str) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
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
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
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
int get_next_word(char **pos, uint32_t *len)
{
	if (!pos || !len || !*pos) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *res = *pos;
	int in_word = 0;
	int done = 0;
	*len = 0;

	while (!done) {
		int c = *res;
		if (c == '\0') {
			done = 1;
			break;
		}

		if (in_word) {
			*pos = res;
			*len = 0;

			while (isalpha(c) || isdigit(c) || (c == '_')) {
				res++;
				c = *res;
				*len += 1;
			}
			done = 1;
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
					done = 1;
					*pos = res;
					*len = ret;
				}
			}
		}
	}
	return 0;
}

/*
 * get next word until the `ch` show up, the blank space is sep
 */
int get_next_word_until(char **str, uint32_t *len, char *chs)
{
	if (!str || !len || !chs || !*str) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *pos = *str;
	*len = 0;
	int flag = 0;

	while (1) {
		if (flag && (strchr(chs, *pos)))
			break;
		if (isspace(*pos)) {
			if (flag)
				break;
			pos++;
			continue;
		}
		if (!flag)
			*str = pos;
		flag = 1;
		*len += 1;
		pos++;
	}
	return 0;
}

#if 0
char *def_seps[] = {
	"<<=", ">>=",
	"...",

	"->", "++", "--", ">>", "<<", "<=", ">=", "==", "!=", "&&", "||", "+=",
	"-=", "*=", "/=", "&=", "^=", "|=", "##", "%=",

	"(", ")", "[", "]", "{", "}", ".", "!", "~", "+", "-", "*", "&", "/",
	"%", "<", ">", "|", "^", "?", ":", "=", ",", ";", "#", "\"", "'",
};
int def_seps_cnt = sizeof(def_seps) / sizeof(char *);
static char *check_tokens_in_seps(char *start, char **seps, int seps_cnt)
{
	int i = 0;

	for (i = 0; i < seps_cnt; i++) {
		size_t str_len = strlen(seps[i]);
		if (!strncmp(start, seps[i], str_len))
			return seps[i];
	}
	return NULL;
}
static char *get_close_paren(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	while (1) {
		if (!*pos)
			return NULL;

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
			break;
		pos++;
	}
	return pos;
}

static char *get_close_braket(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	while (1) {
		if (!*pos)
			return NULL;

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
			break;
		pos++;
	}
	return pos;
}

static char *get_close_brace(char *start)
{
	unsigned long counter = 0;
	char *pos = start;

	while (1) {
		if (!*pos)
			return NULL;

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
			break;
		pos++;
	}
	return pos;
}

/*
 * get_matched_pair: get the position of the paired char
 * return NULL if something goes wrong, return start if not a paired char,
 */
static char *get_matched_pair(char *start)
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
int get_context_in_quote(char **str, uint32_t *len)
{
	if (!str || !len || !*str) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *pos = *str;
	*len = 0;
	char ch = *pos;
	if ((ch != '\'') && (ch != '"')) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	*str = pos+1;
	pos++;

	while (*pos != '\0') {
		if ((*pos == ch) && (*(pos-1) == '\\')) {
			pos++;
			continue;
		}
		if (*pos == ch) {
			*len = pos - *str;
			return 0;
		}
		pos++;
	}
	return -1;
}

/*
 * XXX: all string that malloc terminate with '\0', and the
 * str_len is the argument `malloc` gets, means the real lenth(exclude '\0')
 * list_comm_str_struct_new `len` is the `str` lenth, exclude the '\0'
 */
int list_comm_str_struct_new(list_comm *head, char *str, uint32_t len)
{
	if (!head || !str || (len == (uint32_t)-1)) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	list_comm *new = (list_comm *)malloc(sizeof(list_comm) +
						 sizeof(str_struct));
	if (!new) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}
	memset(new, 0, sizeof(list_comm)+sizeof(str_struct));

	str_struct *data = (str_struct *)new->data;
	data->str = (char *)malloc(len+1);
	if (!data->str) {
		err_dbg(0, err_fmt("malloc err"));
		free(new);
		errno = ENOMEM;
		return -1;
	}
	memset(data->str, 0, len+1);
	memcpy(data->str, str, len);
	data->str_len = len;

	list_comm_append(head, new);
	return 0;
}

void list_comm_str_struct_make_empty(list_comm *head)
{
	list_comm *prev = head, *next = head;
	list_for_each_entry(next, &head->list_head, list_head) {
		str_struct *tmp = (str_struct *)next->data;
		free(tmp->str);
		prev = (list_comm *)next->list_head.prev;
		list_del(&next->list_head);
		free(next);
		next = prev;
	}
	list_comm_init(head);
}

int list_comm_str_struct_comb_free(list_comm *b, list_comm *e)
{
	str_struct *b_data = (str_struct *)b->data;
	str_struct *e_data = (str_struct *)e->data;
	char *tmp = add_str_fau(b_data->str, e_data->str);
	if (!tmp)
		return -1;
	list_del(&e->list_head);
	free(b_data->str);
	free(e_data->str);
	b_data->str = tmp;
	b_data->str_len = strlen(tmp);
	free(e);
	return 0;
}

void list_comm_str_struct_print(list_comm *head)
{
	list_comm *tmp;
	list_for_each_entry(tmp, &head->list_head, list_head) {
		str_struct *tmp_str = (str_struct *)tmp->data;
		fprintf(stdout, "%s\n", tmp_str->str);
	}
}

/*
 * dict key name, valid char exclude '' "" : , { }
 */
static int get_dict_key(char **str, uint32_t *len, char *sep)
{
	if (!str || !len || !sep || !*str) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *pos = *str;
	*len = 0;

	while (*pos != *sep) {
		if (isspace(*pos)) {
			pos++;
			continue;
		}

		if ((*pos == '\'') || (*pos == '"')) {
			get_context_in_quote(&pos, len);
			*str = pos;
			return 0;
		} else {
			get_next_word_until(&pos, len, sep);
			*str = pos;
			return 0;
		}
	}
	return 0;
}

/*
 * the first char *MUST* be the sep `:`
 */
static int get_dict_value(char **str, uint32_t *len, char *sep)
{
	if (!str || !len || !sep || !*str) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *pos = *str;
	*len = 0;
	if (*pos != *sep)
		return -1;
	pos++;

	while (1) {
		if (isspace(*pos)) {
			pos++;
			continue;
		}

		if ((*pos == '\'') || (*pos == '"')) {
			get_context_in_quote(&pos, len);
			*str = pos;
			return 0;
		} else {
			get_next_word_until(&pos, len, ",}");
			*str = pos;
			return 0;
		}
	}
	return 0;
}

/*
 * the input `str` should like this:
 * {"vhost": "1.1.1.1", "host": "2.2.22.2"}
 * every key=value is split by ':', each pair end with ',' or last '}'
 * the whole dict is around a pair of '{' '}'
 * the returned value is a list_dt structure,
 * it's like head<->key<->value<->key<->value<->...<->key<->value<->head
 * XXX: this function is not common use, XXX:should check the head iempty
 * `sep` means the charactor between KEY and VALUE, like `:` `=`
 */
int get_dict_key_value(list_comm *head, char *str, char *sep)
{
	if (!head || !str || !sep) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char *pos = str;
	uint32_t len = 0;
	int cnt_dicts = 0;
	int err;
	list_comm *new_head = head;

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
		if (*pos == '\n')
			break;
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
		err = list_comm_str_struct_new(new_head, pos, len);
		if (err == -1) {
			err_dbg(1,
				  err_fmt("list_comm_str_struct_new err"));
			list_comm_str_struct_make_empty(new_head);
			return -1;
		}
		pos += len;
		char *potmp = pos;
		if (flag_value) {
			potmp = strstr(pos, ",");
			if (!potmp)
				potmp = strstr(pos, "}");
		} else {
			potmp = strstr(pos, sep);
		}
		if (!potmp)
			break;
		if (*potmp == ',')
			potmp++;
		pos = potmp;
	}
	return 0;
}

int str_split(list_comm *head, const char *src, const char *key)
{
	if (!head || !src || !key || (strlen(src) == (size_t)-1)) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	list_comm *tmp_head = head;
	list_comm_init(tmp_head);
	size_t len = strlen(src) + 1;
	char *src_tmp = (char *)malloc(len);
	if (!src_tmp) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}
	memset(src_tmp, 0, len);
	memcpy(src_tmp, src, len);

	char *pob = src_tmp, *poe = NULL;
	int err;
	poe = strstr(pob, key);
	while (poe) {
		*poe = '\0';
		err = list_comm_str_struct_new(tmp_head,pob,strlen(pob));
		if (err) {
			err_dbg(0,
				  err_fmt("list_comm_str_struct_new err"));
			list_comm_str_struct_make_empty(tmp_head);
			free(src_tmp);
			return -1;
		}
		pob = poe + strlen(key);
		poe = strstr(pob, key);
	}

	/* the last one */
	err = 0;
	if (*pob != '\0')
		err = list_comm_str_struct_new(tmp_head,pob,strlen(pob));
	if (err) {
		err_dbg(0, err_fmt("list_comm_str_struct_new err"));
		list_comm_str_struct_make_empty(tmp_head);
		free(src_tmp);
		return -1;
	}

	free(src_tmp);
	return 0;
}
