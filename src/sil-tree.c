#include "../include/sil.h"

static void sil_tree_remove(struct sil_inst *inst, struct sil_tree *tree)
{
	list_del(&tree->sibling);
}

static void sil_tree_destroy(struct sil_inst *inst, struct sil_tree *tree)
{
	/* TODO */
	return;
}

static void sil_tree_debug(FILE *s, struct sil_inst *inst, struct sil_tree *tree)
{
	/* TODO */
	return;
}
