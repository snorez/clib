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
#include "../include/clib_cmd.h"

static LIST_HEAD(cmd_head);
static lock_t cmd_head_lock;

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

	read_lock(&cmd_head_lock);
	list_for_each_entry(node, &cmd_head, list_head) {
		if ((!skip_done) && (i < idx)) {
			i++;
			continue;
		}
		idx++;
		skip_done = 1;
		str_struct *s = (void *)node->data;
		if (!strncmp(s->str, text, len)) {
			read_unlock(&cmd_head_lock);
			return xdupstr(s->str);
		}
	}
	read_unlock(&cmd_head_lock);

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

static sigjmp_buf rl_jmp_env;
static int sigint_is_set = 0;
static void rl_sigint(int signo)
{
	siglongjmp(rl_jmp_env, 1);
}

char *clib_readline_add_history(char *prompt)
{
	char *ret;
	if (unlikely(!sigint_is_set)) {
		sigint_is_set = 1;
		signal(SIGINT, rl_sigint);
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
		err_dbg(1, err_fmt("readline err"));
		return NULL;
	} else if (!*ret)
		goto redo;
	add_history(ret);
	return ret;
}

int clib_cmd_ac_add(char *buf)
{
	list_comm *node;
	write_lock(&cmd_head_lock);
	list_for_each_entry(node, &cmd_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (!strcmp(s->str, buf)) {
			read_unlock(&cmd_head_lock);
			return 0;
		}
	}

	int err = list_comm_str_struct_new((void *)&cmd_head, buf, strlen(buf));
	write_unlock(&cmd_head_lock);
	return err;
}

void clib_cmd_ac_del(char *buf)
{
	list_comm *node;
	write_lock(&cmd_head_lock);
	list_for_each_entry(node, &cmd_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (strcmp(s->str, buf))
			continue;
		list_del(&node->list_head);
		free(s->str);
		free(node);
		write_unlock(&cmd_head_lock);
		return;
	}
	write_unlock(&cmd_head_lock);
}

void clib_cmd_ac_cleanup(void)
{
	write_lock(&cmd_head_lock);
	list_comm_str_struct_make_empty((void *)&cmd_head);
	write_unlock(&cmd_head_lock);
}

static lock_t cmds___lock = {0};
static struct clib_cmd cmds[CLIB_CMD_MAX] = { 0 };
static struct clib_cmd *cmds_user = NULL;
static int cmds_user_cnt = 0;

struct clib_cmd *clib_cmd_find(char *name)
{
	int i = 0;
	struct clib_cmd *b = NULL;
	int cnt = 0;

	if (cmds_user) {
		b = cmds_user;
		cnt = cmds_user_cnt;
	} else {
		b = cmds;
		cnt = CLIB_CMD_MAX;
	}

	for (i = 0; i < cnt; i++) {
		if (!b[i].cmd)
			continue;
		if ((!strcmp(name, b[i].cmd))) {
			atomic_inc(&b[i].refcount);
			return &b[i];
		}
	}
	return NULL;
}

static void clib_cmd_put(struct clib_cmd *c)
{
	if (atomic_dec_and_test(&c->refcount)) {
		clib_cmd_ac_del(c->cmd);
		memset(c, 0, sizeof(*c));
	}
}

long clib_cmd_add(struct clib_cmd *newcmd)
{
	int i = 0, err = 0;
	write_lock(&cmds___lock);
	struct clib_cmd *old = clib_cmd_find(newcmd->cmd);
	if (old) {
		atomic_dec(&old->refcount);
		write_unlock(&cmds___lock);
		err_ret(0, -EEXIST, err_fmt("cmd %s already exists"), newcmd->cmd);
	}

	struct clib_cmd *b = NULL;
	int cnt = 0;
	if (cmds_user) {
		b = cmds_user;
		cnt = cmds_user_cnt;
	} else {
		b = cmds;
		cnt = CLIB_CMD_MAX;
	}

	for (i = 0; i < cnt; i++) {
		if (!b[i].cmd)
			break;
	}

	if (i == cnt) {
		write_unlock(&cmds___lock);
		err_ret(0, -EDQUOT, err_fmt("cmd cnt exceed"));
	}

	b[i] = *newcmd;
	atomic_set(&b[i].refcount, 1);
	err = clib_cmd_ac_add(b[i].cmd);
	if (err) {
		memset(&b[i], 0, sizeof(b[i]));
		write_unlock(&cmds___lock);
		err_retval(0, err, err_fmt("clib_cmd_ac_add err"));
	}
	write_unlock(&cmds___lock);
	fprintf(stdout, "NEW CMD: %s\n", b[i].cmd);
	if (b[i].usage) {
		fprintf(stdout, "USAGE:\n");
		b[i].usage();
	}
	return 0;
}

long clib_cmd_add_array(struct clib_cmd *cs, int cs_cnt)
{
	int err = 0;
	for (int i = 0; i < cs_cnt; i++) {
		read_lock(&cmds___lock);
		if (!cs[i].cmd) {
			read_unlock(&cmds___lock);
			continue;
		}
		read_unlock(&cmds___lock);
		err = clib_cmd_add(&cs[i]);
		if (err) {
			if (errno == EEXIST)
				continue;
			clib_cmd_cleanup();
			err_dbg(0, err_fmt("clib_cmd_add err"));
			goto set_cmds_user;
		}
	}
	if (!err)
		return 0;

set_cmds_user:
	write_lock(&cmds___lock);
	cmds_user = cs;
	cmds_user_cnt = cs_cnt;
	write_unlock(&cmds___lock);
	return 0;
}

void clib_cmd_del(char *name)
{
	write_lock(&cmds___lock);
	struct clib_cmd *old = clib_cmd_find(name);
	if (!old) {
		err_dbg(0, err_fmt("cmd %s not found"), name);
		write_unlock(&cmds___lock);
		return;
	}
	clib_cmd_put(old);
	clib_cmd_put(old);
	write_unlock(&cmds___lock);
}

void clib_cmd_cleanup(void)
{
	int i = 0;
	struct clib_cmd *b = NULL;
	int cnt = 0;
	write_lock(&cmds___lock);
	if (cmds_user) {
		b = cmds_user;
		cnt = cmds_user_cnt;
	} else {
		b = cmds;
		cnt = CLIB_CMD_MAX;
	}

	for (i = 0; i < cnt; i++) {
		if (!b[i].cmd)
			continue;
		clib_cmd_ac_del(b[i].cmd);
		memset(&b[i], 0, sizeof(b[i]));
	}
	write_unlock(&cmds___lock);
}

long clib_cmd_exec(char *cmd, int argc, char **argv)
{
	struct clib_cmd *t = clib_cmd_find(cmd);
	if (!t)
		err_ret(0, -ENOENT, err_fmt("cmd %s not found"), cmd);

	long ret = 0;
	if (t->cb) {
		ret = t->cb(argc, argv);
	} else {
		ret = -EINVAL;
		err_dbg(0, err_fmt("cmd %s has no callback function"), cmd);
	}
	clib_cmd_put(t);
	return ret;
}

void clib_cmd_usages(void)
{
	int i = 0;
	struct clib_cmd *b = NULL;
	int cnt = 0;
	read_lock(&cmds___lock);
	if (cmds_user) {
		b = cmds_user;
		cnt = cmds_user_cnt;
	} else {
		b = cmds;
		cnt = CLIB_CMD_MAX;
	}

	fprintf(stdout, "========= USAGE INFO =========\n");
	for (i = 0; i < cnt; i++) {
		if (!b[i].cmd)
			continue;
		fprintf(stdout, "%s:\n", b[i].cmd);
		if (b[i].usage)
			b[i].usage();
		else
			fprintf(stdout, "\tcommand has no usage\n");
	}
	fprintf(stdout, "========= USAGE END =========\n");
	read_unlock(&cmds___lock);
}

long clib_cmd_getarg(char *buf, size_t buflen, int *argc, char **argv)
{
	char *pos = buf;
	if (pos[buflen-1])
		err_ret(0, -EINVAL, err_fmt("input format err"));

	int in_word = 0;
	*argc = 0;
	while (*pos) {
		if (isspace(*pos)) {
			if (in_word)
				in_word = 0;
			*pos = '\0';
		} else if (!in_word) {
			if (*argc >= CMD_ARGS_MAX)
				err_ret(0, -EINVAL, err_fmt("cmd args too many"));
			argv[*argc] = pos;
			*argc = *argc + 1;
			in_word = 1;
		}
		pos++;
	}
	return 0;
}
