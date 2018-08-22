#include "../include/clib_cmd_auto_completion.h"

static LIST_HEAD(buf_head);

static char *xdupstr(char *str)
{
	char *ret = (char *)malloc(strlen(str)+1);
	if (!ret)
		return NULL;
	memcpy(ret, str, strlen(str)+1);
	return ret;
}

static char *clib_generator(const char *text, int state)
{
	static size_t idx = 0, len = 0;
	size_t i = 0, skip_done = 0;
	list_comm *node;

	if (!state) {
		idx = 0;
		len = strlen(text);
	}

	list_for_each_entry(node, &buf_head, list_head) {
		if ((!skip_done) && (i < idx)) {
			i++;
			continue;
		}
		idx++;
		skip_done = 1;
		str_struct *s = (void *)node->data;
		if (!strncmp(s->str, text, len))
			return xdupstr(s->str);
	}

	return NULL;
}

static char **clib_completion(const char *text, int start, int end)
{
	char **matches = (char **)NULL;

	if (start == 0)
		matches = rl_completion_matches((char *)text, &clib_generator);

	return matches;
}

void clib_set_cmd_completor(void)
{
	rl_attempted_completion_function = clib_completion;
}

char *clib_readline_add_history(char *prompt)
{
	char *ret = readline(prompt);
	if (!ret) {
		err_dbg(1, err_fmt("readline err"));
		return NULL;
	}
	add_history(ret);
	return ret;
}

int clib_cmd_add(char *buf)
{
	list_comm *node;
	list_for_each_entry(node, &buf_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (!strcmp(s->str, buf))
			return 0;
	}
	return list_comm_str_struct_new((void *)&buf_head, buf, strlen(buf));
}

void clib_cmd_del(char *buf)
{
	list_comm *node;
	list_for_each_entry(node, &buf_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (strcmp(s->str, buf))
			continue;
		list_del(&node->list_head);
		free(s->str);
		free(node);
	}
}

void clib_cmd_cleanup(void)
{
	list_comm_str_struct_make_empty((void *)&buf_head);
}
