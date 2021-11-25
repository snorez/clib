#include "../include/sil.h"

static struct sil_token *sil_token_alloc(struct sil_inst *inst)
{
	struct sil_token *_new;
	_new = (struct sil_token *)xmalloc(sizeof(*_new));
	if (!_new) {
		SIL_LOG(inst, errno, "xmalloc err");
	}
	memset(_new, 0, sizeof(*_new));
	return _new;
}

static void sil_token_free(struct sil_inst *inst, struct sil_token *token)
{
	free(token);
}

static void sil_token_insert(struct sil_inst *inst, struct sil_token *token)
{
	list_add_tail(&token->sibling, &inst->tokens);
}

static void sil_token_remove(struct sil_inst *inst, struct sil_token *token)
{
	list_del(&token->sibling);
}

static struct sil_token *sil_token_new(struct sil_inst *inst, char *token,
				       int line, int col)
{
	struct sil_token *_new;
	_new = sil_token_alloc(inst);

	_new->token = (char *)xmalloc(strlen(token) + 1);
	if (!_new->token) {
		SIL_LOG(inst, errno, "xmalloc err");
		sil_token_free(inst, _new);
		return NULL;
	}

	memcpy(_new->token, token, strlen(token) + 1);
	_new->line = line;
	_new->col = col;
	return _new;
}

static void sil_token_destroy(struct sil_inst *inst, struct sil_token *token)
{
	free(token->token);
	sil_token_free(inst, token);
}

static void sil_token_debug(FILE *s, struct sil_inst *inst, struct sil_token *token)
{
	fprintf(s, "\t(0x%04x 0x%04x): %s\n",
		(unsigned)token->line, (unsigned)token->col, token->token);
}
