#include "../include/sil.h"

static void sil_inst_log(struct sil_inst *inst, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if ((!inst) || (!inst->log_f)) {
		_err_common(stderr, 1, error, fmt, ap);
	} else {
		_err_common(inst->log_f, 0, error, fmt, ap);
	}

	va_end(ap);
}

static struct sil_inst *sil_inst_alloc(void)
{
	struct sil_inst *_new;
	_new = (struct sil_inst *)xmalloc(sizeof(*_new));
	if (!_new) {
		SIL_LOG(NULL, errno, "xmalloc err");
		return NULL;
	}

	memset(_new, 0, sizeof(*_new));

	INIT_LIST_HEAD(&_new->tokens);
	INIT_LIST_HEAD(&_new->symtab);

	return _new;
}

static void sil_inst_free(struct sil_inst *inst)
{
	free(inst);
}

static struct sil_inst *sil_inst_new(const char *infile, const char *logfile)
{
	struct sil_inst *_new;
	_new = sil_inst_alloc();
	if (!_new) {
		SIL_LOG(NULL, 0, "sil_inst_alloc err");
		return NULL;
	}

	_new->infile = infile;
	_new->logfile = logfile;

	return _new;
}

static void sil_inst_destroy(struct sil_inst *inst)
{
	struct sil_token *tmp_token, *next_token;
	list_for_each_entry_safe(tmp_token, next_token, &inst->tokens, sibling) {
		sil_token_remove(inst, tmp_token);
		sil_token_destroy(inst, tmp_token);
	}

	struct sil_tree *tmp_tree, *next_tree;
	list_for_each_entry_safe(tmp_tree, next_tree, &inst->symtab, sibling) {
		sil_tree_remove(inst, tmp_tree);
		sil_tree_destroy(inst, tmp_tree);
	}

	if (inst->infile_content)
		free(inst->infile_content);
	if (inst->log_f)
		fclose(inst->log_f);

	sil_inst_free(inst);
}

static int sil_inst_open_log(struct sil_inst *inst)
{
	inst->log_f = fopen(inst->logfile, "w+");
	if (!inst->log_f) {
		SIL_LOG(inst, errno, "fopen %s err", inst->logfile);
		return -1;
	}

	return 0;
}

static int sil_inst_load_infile(struct sil_inst *inst)
{
	inst->infile_content = clib_loadfile(inst->infile, NULL);
	if (!inst->infile_content) {
		SIL_LOG(inst, 0, "clib_loadfile %s err", inst->infile);
		return -1;
	}

	return 0;
}

static int sil_inst_prepare(struct sil_inst *inst)
{
	int err;

	err = sil_inst_open_log(inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_inst_open_log err");
		return -1;
	}

	err = sil_inst_load_infile(inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_inst_load_infile err");
		return -1;
	}

	return 0;
}

static void sil_inst_debug(struct sil_inst *inst, const char *outfile)
{
	FILE *s = fopen(outfile, "w");
	if (!s) {
		SIL_LOG(inst, errno, "fopen %s err", outfile);
		return;
	}

	fprintf(s, "INFILE: %s\n", inst->infile);
	fprintf(s, "LOGFILE: %s\n", inst->logfile);

	fprintf(s, "TOKENS:\n");
	struct sil_token *tmp_token;
	list_for_each_entry(tmp_token, &inst->tokens, sibling) {
		sil_token_debug(s, inst, tmp_token);
	}

	fprintf(s, "SYMTAB:\n");
	struct sil_tree *tmp_tree;
	list_for_each_entry(tmp_tree, &inst->symtab, sibling) {
		sil_tree_debug(s, inst, tmp_tree);
	}

	fflush(s);
	fclose(s);
	return;
}
