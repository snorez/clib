#include "../include/sil.h"

static struct sil_internal_fn def_internal_fns[] = {
};

static struct sil_internal_fn *sil_internal_fn_alloc(void)
{
	struct sil_internal_fn *_new;
	_new = (struct sil_internal_fn *)xmalloc(sizeof(*_new));
	if (!_new) {
		SIL_LOG(NULL, errno, "xmalloc err");
		return NULL;
	}

	memset(_new, 0, sizeof(*_new));

	return _new;
}

static void sil_internal_fn_free(struct sil_internal_fn *ifn)
{
	free(ifn);
}

static struct sil_internal_fn *sil_internal_fn_new(char *name,
						   int (*h)(void *, void (*cb)(void *)))
{
	struct sil_internal_fn *ifn;
	ifn = sil_internal_fn_alloc();
	if (!ifn) {
		SIL_LOG(NULL, 0, "sil_internal_fn_alloc err");
		return NULL;
	}

	ifn->name = name;
	ifn->handler = h;

	return ifn;
}

static void sil_internal_fn_destroy(struct sil_internal_fn *ifn)
{
	sil_internal_fn_free(ifn);
}
