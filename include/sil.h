#ifndef SIL_H_SGCAEGR8
#define SIL_H_SGCAEGR8

#include "../include/clib.h"

DECL_BEGIN

struct sil_inst {
	const char		*infile;
	const char		*logfile;

	char			*infile_content;
	FILE			*log_f;

	struct list_head	tokens;
	struct list_head	symtab;
};

struct sil_token {
	struct list_head	sibling;
	char			*token;
	int			line;
	int			col;
};

struct sil_tree {
	struct list_head	sibling;
	/* TODO */
};

struct sil_function_decl {
	struct sil_tree		base;
	/* TODO */
};

struct sil_parm_decl {
	struct sil_tree		base;
	/* TODO */
};

struct sil_var_decl {
	struct sil_tree		base;
	/* TODO */
};

struct sil_result_decl {
	struct sil_tree		base;
	/* TODO */
};

struct sil_int {
	struct sil_tree		base;
	/* TODO */
};

struct sil_str {
	struct sil_tree		base;
	/* TODO */
};

struct sil_bb {
	/* TODO */
};

struct sil_stmt {
	/* TODO */
};

struct sil_cond {
	struct sil_stmt		base;
	/* TODO */
};

struct sil_ud_call {
	struct sil_stmt		base;
	/* TODO */
};

struct sil_internal_call {
	struct sil_stmt		base;
	/* TODO */
};

struct sil_assign {
	struct sil_stmt		base;
	/* TODO */
};

struct sil_keyword {
	struct list_head	sibling;
	char			*keyword;
	int			(*handler)(void *);
};

struct sil_internal_fn {
	struct list_head	sibling;
	char			*name;
	int			(*handler)(void *, void (*cb)(void *));
};

struct sil {
	const char		*name;
	struct list_head	keywords;
	struct list_head	internal_fns;
	int			(*tokenize)(struct sil *, struct sil_inst *);
	int			(*symbolize)(struct sil *, struct sil_inst *);
	int			(*run)(struct sil *, struct sil_inst *);
};

C_SYM struct sil *sil_new(const char *name,
			  struct sil_keyword *keywords, size_t keyword_cnt,
			  struct sil_internal_fn *internal_fns, size_t fn_cnt,
			  int (*tokenize)(struct sil *, struct sil_inst *),
			  int (*symbolize)(struct sil *, struct sil_inst *),
			  int (*run)(struct sil *, struct sil_inst *));
C_SYM int sil_run_script(struct sil *sil, const char *infile,
			 const char *logfile, const char *debugfile);
C_SYM void sil_destroy(struct sil *sil);

DECL_END

#endif /* end of include guard: SIL_H_SGCAEGR8 */
