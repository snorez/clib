#include "../include/sil.h"

static void sil_inst_log(struct sil_inst *inst, int error, const char *fmt, ...);
#define	SIL_LOG(inst, errc, fmt, ...) sil_inst_log(inst, errc, err_fmt(fmt), ##__VA_ARGS__)

static void sil_token_remove(struct sil_inst *inst, struct sil_token *token);
static void sil_token_destroy(struct sil_inst *inst, struct sil_token *token);
static void sil_token_debug(FILE *s, struct sil_inst *inst, struct sil_token *token);

static void sil_tree_remove(struct sil_inst *inst, struct sil_tree *tree);
static void sil_tree_destroy(struct sil_inst *inst, struct sil_tree *tree);
static void sil_tree_debug(FILE *s, struct sil_inst *inst, struct sil_tree *tree);

#include "sil-keyword.c"
#include "sil-internal.c"
#include "sil-inst.c"
#include "sil-token.c"
#include "sil-tokenizer.c"
#include "sil-tree.c"
#include "sil-stmt.c"
#include "sil-bb.c"
#include "sil-symtab.c"
#include "sil-runtime.c"

static struct sil *sil_alloc(void)
{
	struct sil *_new;
	_new = (struct sil *)xmalloc(sizeof(*_new));
	if (!_new) {
		SIL_LOG(NULL, errno, "xmalloc err");
		return NULL;
	}

	memset(_new, 0, sizeof(*_new));

	return _new;
}

static void sil_free(struct sil *sil)
{
	free(sil);
}

static int sil_add_keyword(struct sil *sil, char *keyword, int (*handler)(void *))
{
	struct sil_keyword *kw;
	kw = sil_keyword_new(keyword, handler);
	if (!kw) {
		SIL_LOG(NULL, 0, "sil_keyword_new err");
		return -1;
	}

	list_add_tail(&kw->sibling, &sil->keywords);
	return 0;
}

static void sil_del_keyword(struct sil *sil, struct sil_keyword *kw)
{
	list_del(&kw->sibling);

	sil_keyword_destroy(kw);
}

static int sil_init_keywords(struct sil *sil, struct sil_keyword *keywords,
			     size_t count, int no_default)
{
	int err = 0;

	if (!no_default) {
		for (size_t i = 0; i < ARRAY_CNT(def_keywords); i++) {
			err = sil_add_keyword(sil, def_keywords[i].keyword,
					      def_keywords[i].handler);
			if (err == -1)
				return -1;
		}
	}

	for (size_t i = 0; i < count; i++) {
		err = sil_add_keyword(sil, keywords[i].keyword,
				      keywords[i].handler);
		if (err == -1)
			return -1;
	}

	return 0;
}

static int sil_add_internal_fn(struct sil *sil, char *name,
			       int (*h)(void *, void (*cb)(void *)))
{
	struct sil_internal_fn *ifn;
	ifn = sil_internal_fn_new(name, h);
	if (!ifn) {
		SIL_LOG(NULL, 0, "sil_internal_fn_new err");
		return -1;
	}

	list_add_tail(&ifn->sibling, &sil->internal_fns);
	return 0;
}

static void sil_del_internal_fn(struct sil *sil, struct sil_internal_fn *ifn)
{
	list_del(&ifn->sibling);

	sil_internal_fn_destroy(ifn);
}

static int sil_init_internal_fns(struct sil *sil,
				 struct sil_internal_fn *internal_fns,
				 size_t count, int no_default)
{
	int err = 0;

	if (!no_default) {
		for (size_t i = 0; i < ARRAY_CNT(def_internal_fns); i++) {
			err = sil_add_internal_fn(sil,
						  def_internal_fns[i].name,
						  def_internal_fns[i].handler);
			if (err == -1)
				return -1;
		}
	}

	for (size_t i = 0; i < count; i++) {
		err = sil_add_internal_fn(sil,
					  internal_fns[i].name,
					  internal_fns[i].handler);
		if (err == -1)
			return -1;
	}

	return 0;
}

struct sil *sil_new(const char *name,
		    struct sil_keyword *keywords, size_t keyword_cnt,
		    struct sil_internal_fn *internal_fns, size_t internal_fn_cnt,
		    int (*tokenize)(struct sil *, struct sil_inst *),
		    int (*symbolize)(struct sil *, struct sil_inst *),
		    int (*run)(struct sil *, struct sil_inst *))
{
	int err = 0;
	struct sil *sil;

	sil = sil_alloc();
	if (!sil) {
		SIL_LOG(NULL, 0, "sil_alloc err");
		return NULL;
	}

	INIT_LIST_HEAD(&sil->keywords);
	INIT_LIST_HEAD(&sil->internal_fns);

	sil->name = name;

	err = sil_init_keywords(sil, keywords, keyword_cnt, tokenize ? 1 : 0);
	if (err == -1) {
		SIL_LOG(NULL, 0, "sil_init_keywords err");
		goto err_out;
	}

	err = sil_init_internal_fns(sil, internal_fns, internal_fn_cnt,
				    tokenize ? 1 : 0);
	if (err == -1) {
		SIL_LOG(NULL, 0, "sil_init_internal_fns err");
		goto err_out;
	}

	if (!tokenize)
		sil->tokenize = sil_tokenize;

	if (!symbolize)
		sil->symbolize = sil_symbolize;

	if (!run)
		sil->run = sil_run;

	return sil;

err_out:
	sil_destroy(sil);
	return NULL;
}

int sil_run_script(struct sil *sil, const char *infile,
		   const char *logfile, const char *debugfile)
{
	int err = 0;
	struct sil_inst *inst;

	inst = sil_inst_new(infile, logfile);
	if (!inst) {
		SIL_LOG(inst, 0, "sil_inst_new err");
		return -1;
	}

	err = sil_inst_prepare(inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_inst_prepare err");
		err = -1;
		goto destroy_out;
	}

	err = sil->tokenize(sil, inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_inst_tokenize err");
		err = -1;
		goto destroy_out;
	}

	err = sil->symbolize(sil, inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_gimplify err");
		err = -1;
		goto destroy_out;
	}

	if (debugfile) {
		sil_inst_debug(inst, debugfile);
	}

	err = sil->run(sil, inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "sil_run err");
		err = -1;
		goto destroy_out;
	}

destroy_out:
	sil_inst_destroy(inst);

	return err;
}

void sil_destroy(struct sil *sil)
{
	struct sil_keyword *tmp_kw, *next_kw;
	list_for_each_entry_safe(tmp_kw, next_kw, &sil->keywords, sibling) {
		sil_del_keyword(sil, tmp_kw);
	}

	struct sil_internal_fn *tmp_ifn, *next_ifn;
	list_for_each_entry_safe(tmp_ifn, next_ifn, &sil->internal_fns, sibling) {
		sil_del_internal_fn(sil, tmp_ifn);
	}

	sil_free(sil);

	return;
}
