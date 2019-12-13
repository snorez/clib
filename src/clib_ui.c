/*
 * for user interaction: command autocomplete and command execution
 * This should NOT use in multi-thread process
 *
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
#include "../include/clib_ui.h"

/* use [0] as the default ui_env */
static struct clib_ui_env ui_env[CLIB_UI_MAX_DEPTH] = {
	[0] = {LIST_HEAD_INIT(ui_env[0].cmd_head),
		LIST_HEAD_INIT(ui_env[0].ac_head)},
};
static int ui_idx = 0;

static char *xdupstr(char *str)
{
	if (!str) {
		err_msg("BUG: NULL str");
		return NULL;
	}

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

	if (!text) {
		err_msg("BUG: NULL text");
		return NULL;
	}

	if (!state) {
		idx = 0;
		len = strlen(text);
	}

	list_for_each_entry(node, &ui_env[ui_idx].ac_head, list_head) {
		if ((!skip_done) && (i < idx)) {
			i++;
			continue;
		}
		idx++;
		skip_done = 1;
		buf_struct *s = (void *)node->data;
		if (!strncmp(s->buf, text, len))
			return xdupstr(s->buf);
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

int clib_ui_begin(void)
{
	ui_idx++;
	if (ui_idx >= CLIB_UI_MAX_DEPTH) {
		err_dbg(0, "ui_idx too many");
		ui_idx--;
		return -1;
	}

	INIT_LIST_HEAD(&ui_env[ui_idx].cmd_head);
	INIT_LIST_HEAD(&ui_env[ui_idx].ac_head);
	return 0;
}

void clib_ui_end(void)
{
	if (!ui_idx)
		return;
	ui_idx--;
}

static sigjmp_buf rl_jmp_env;
static int sigint_is_set = 0;
static void rl_sigint(int signo)
{
	siglongjmp(rl_jmp_env, 1);
}

static char new_prompt[64];
char *clib_readline(char *prompt)
{
	char *ret;
	if (unlikely(!sigint_is_set)) {
		rl_attempted_completion_function = clib_completion;
		sigint_is_set = 1;
		signal(SIGINT, rl_sigint);
	}

	if (ui_idx) {
		int idx = ui_idx;
		int i = 0;
		while (idx) {
			i++;
			idx = idx / 10;
		}
		size_t newlen = strlen(prompt) + 1 + i + 2 + 1;
		if (newlen <= 64) {
			snprintf(new_prompt, newlen, "<%d> %s", ui_idx, prompt);
			prompt = new_prompt;
		}
	}

redo:
	if (sigsetjmp(rl_jmp_env, 1)) {
		fprintf(stdout, "\n");
		fflush(stdin);
		fflush(stdout);
		fflush(stderr);
	}
	ret = readline(prompt);
	if (!ret) {
		err_dbg(1, "readline err");
		return NULL;
	} else if (!*ret)
		goto redo;
	add_history(ret);
	return ret;
}

static struct clib_cmd *clib_cmd_new(char *name,
					clib_cmd_cb cb,
					clib_cmd_usage usage)
{
	struct clib_cmd *_new;
	_new = malloc(sizeof(*_new));
	if (!_new) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(_new, 0, sizeof(*_new));

	_new->cmd = malloc(strlen(name)+1);
	if (!_new->cmd) {
		err_dbg(0, "malloc err");
		goto err_out0;
	}
	memcpy(_new->cmd, name, strlen(name)+1);
	INIT_LIST_HEAD(&_new->sibling);
	_new->cb = cb;
	_new->usage = usage;
	return _new;

err_out0:
	free(_new);
	return NULL;
}

static void clib_cmd_free(struct clib_cmd *c)
{
	free(c->cmd);
	free(c);
}

struct clib_cmd *clib_cmd_find(char *name)
{
	struct clib_cmd *tmp;

	list_for_each_entry(tmp, &ui_env[ui_idx].cmd_head, sibling) {
		if (!strcmp(name, tmp->cmd))
			return tmp;
	}

	return NULL;
}

long clib_cmd_add(char *name, clib_cmd_cb cb, clib_cmd_usage usage)
{
	if (unlikely(!name)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	struct clib_cmd *old = clib_cmd_find(name);
	if (old) {
		err_dbg(0, "cmd %s already exists", name);
		return -1;
	}

	struct clib_cmd *newcmd = clib_cmd_new(name, cb, usage);
	if (!newcmd) {
		err_dbg(0, "clib_cmd_new err");
		return -1;
	}

	list_add_tail(&newcmd->sibling, &ui_env[ui_idx].cmd_head);
#if 0
	fprintf(stdout, "NEW CMD: %s\n", newcmd->cmd);
	if (newcmd->usage) {
		fprintf(stdout, "USAGE:\n");
		newcmd->usage();
	}
#endif

	return 0;
}

void clib_cmd_del(char *name)
{
	if (unlikely(!name)) {
		err_dbg(0, "arg check err");
		return;
	}

	struct clib_cmd *old = clib_cmd_find(name);
	if (!old) {
		err_dbg(0, "cmd %s not found", name);
		return;
	}
	list_del_init(&old->sibling);
	clib_cmd_free(old);
}

void clib_cmd_cleanup(void)
{
	struct clib_cmd *cur, *next;
	list_for_each_entry_safe(cur, next, &ui_env[ui_idx].cmd_head, sibling) {
		list_del_init(&cur->sibling);
		clib_cmd_free(cur);
	}
	BUG_ON(!list_empty(&ui_env[ui_idx].cmd_head));
}

long clib_cmd_exec(char *cmd, int argc, char **argv)
{
	if (unlikely(!cmd)) {
		err_dbg(0, "arg check err");
		return -1;
	}

	struct clib_cmd *t = clib_cmd_find(cmd);
	if (!t) {
		err_dbg(0, "cmd %s not found", cmd);
		return -1;
	}

	long ret = 0;
	if (t->cb) {
		ret = t->cb(argc, argv);
	} else {
		err_dbg(0, "cmd %s has no callback function", cmd);
		ret = -1;
	}
	return ret;
}

void clib_cmd_usages(void)
{
	struct clib_cmd *tmp;

	fprintf(stdout, "================== USAGE INFO ==================\n");
	list_for_each_entry(tmp, &ui_env[ui_idx].cmd_head, sibling) {
		fprintf(stdout, "%s\n", tmp->cmd);
		if (tmp->usage)
			tmp->usage();
		else
			fprintf(stdout, "\tcommand has no usage\n");
	}
	fprintf(stdout, "================== USAGE END ==================\n");
}

long clib_cmd_getarg(char *buf, size_t buflen, int *argc, char **argv, int argv_cnt)
{
	char *pos = buf;
	if (unlikely(pos[buflen-1])) {
		err_dbg(0, "input too long");
		return -1;
	}

	int in_word = 0;
	*argc = 0;
	while (*pos) {
		if (isspace(*pos)) {
			if (in_word)
				in_word = 0;
			*pos = '\0';
		} else if (!in_word) {
			if (*argc >= argv_cnt) {
				err_dbg(0, "args too many");
				return -1;
			}
			argv[*argc] = pos;
			*argc = *argc + 1;
			in_word = 1;
		}
		pos++;
	}
	return 0;
}

int clib_ac_add(char *str)
{
	list_comm *node;
	list_for_each_entry(node, &ui_env[ui_idx].ac_head, list_head) {
		buf_struct *s = (buf_struct *)node->data;
		if (!strcmp(s->buf, str))
			return 0;
	}

	int err = buf_struct_new_append((void *)&ui_env[ui_idx].ac_head,
					str, strlen(str));
	return err;
}

void clib_ac_del(char *str)
{
	list_comm *node, *next;
	list_for_each_entry_safe(node, next,
				&ui_env[ui_idx].ac_head, list_head) {
		buf_struct *s = (buf_struct *)node->data;
		if (strcmp(s->buf, str))
			continue;
		list_del(&node->list_head);
		free(s->buf);
		free(node);
		return;
	}
}

void clib_ac_cleanup(void)
{
	buf_struct_list_cleanup((void *)&ui_env[ui_idx].ac_head);
	BUG_ON(!list_empty(&ui_env[ui_idx].ac_head));
}

long clib_cmd_ac_add(char *name, clib_cmd_cb cb, clib_cmd_usage usage)
{
	long err;

	err = clib_cmd_add(name, cb, usage);
	if (err == -1) {
		err_dbg(0, "clib_cmd_add err");
		return -1;
	}

	err = clib_ac_add(name);
	if (err == -1) {
		err_dbg(0, "clib_ac_add err");
		clib_cmd_del(name);
		return -1;
	}

	return 0;
}

void clib_cmd_ac_del(char *name)
{
	clib_cmd_del(name);
	clib_ac_del(name);
}

void clib_cmd_ac_cleanup(void)
{
	clib_cmd_cleanup();
	clib_ac_cleanup();
}
