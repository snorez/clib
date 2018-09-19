#include "../include/clib.h"

static LIST_HEAD(cmd_head);

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

	list_for_each_entry(node, &cmd_head, list_head) {
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
	char *ret;
redo:
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
	list_for_each_entry(node, &cmd_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (!strcmp(s->str, buf))
			return 0;
	}
	return list_comm_str_struct_new((void *)&cmd_head, buf, strlen(buf));
}

void clib_cmd_ac_del(char *buf)
{
	list_comm *node;
	list_for_each_entry(node, &cmd_head, list_head) {
		str_struct *s = (str_struct *)node->data;
		if (strcmp(s->str, buf))
			continue;
		list_del(&node->list_head);
		free(s->str);
		free(node);
		return;
	}
}

void clib_cmd_ac_cleanup(void)
{
	list_comm_str_struct_make_empty((void *)&cmd_head);
}

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
		if ((!strcmp(name, b[i].cmd)))
			return &b[i];
	}
	return NULL;
}

long clib_cmd_add(struct clib_cmd *newcmd)
{
	int i = 0, err = 0;
	struct clib_cmd *old = clib_cmd_find(newcmd->cmd);
	if (old) {
		err_dbg(0, err_fmt("cmd %s already exists"), newcmd->cmd);
		return -1;
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
		err_dbg(0, err_fmt("cmd cnt exceed"));
		return -1;
	}

	b[i] = *newcmd;
	err = clib_cmd_ac_add(b[i].cmd);
	if (err) {
		err_dbg(0, err_fmt("clib_cmd_ac_add err"));
		memset(&b[i], 0, sizeof(b[i]));
		return -1;
	}
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
		if (!cs[i].cmd)
			continue;
		err = clib_cmd_add(&cs[i]);
		if (err) {
			err_dbg(0, err_fmt("clib_cmd_add err"));
			clib_cmd_cleanup();
			goto set_cmds_user;
		}
	}
	if (!err)
		return 0;

set_cmds_user:
	cmds_user = cs;
	cmds_user_cnt = cs_cnt;
	return 0;
}

void clib_cmd_del(char *name)
{
	struct clib_cmd *old = clib_cmd_find(name);
	if (!old) {
		err_dbg(0, err_fmt("cmd %s not found"), name);
		return;
	}
	clib_cmd_ac_del(old->cmd);
	memset(old, 0, sizeof(*old));
}

void clib_cmd_cleanup(void)
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
		clib_cmd_ac_del(b[i].cmd);
		memset(&b[i], 0, sizeof(b[i]));
	}
}

long clib_cmd_exec(char *cmd, int argc, char **argv)
{
	struct clib_cmd *t = clib_cmd_find(cmd);
	if (!t) {
		err_dbg(0, err_fmt("cmd %s not found"), cmd);
		return -1;
	}

	if (t->cb) {
		return t->cb(argc, argv);
	} else {
		err_dbg(0, err_fmt("cmd %s has no callback function"));
		return -1;
	}
}

void clib_cmd_usages(void)
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
}

long clib_cmd_getarg(char *buf, size_t buflen, int *argc, char **argv)
{
	char *pos = buf;
	if (pos[buflen-1]) {
		err_dbg(0, err_fmt("input format error\n"));
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
			if (*argc >= CMD_ARGS_MAX) {
				err_dbg(0, err_fmt("cmd args too many"));
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
