#include "../include/sil.h"

static struct sil_keyword def_keywords[] = {
};

static struct sil_keyword *sil_keyword_alloc(void)
{
	struct sil_keyword *_new;
	_new = (struct sil_keyword *)xmalloc(sizeof(*_new));
	if (!_new) {
		SIL_LOG(NULL, errno, "xmalloc err");
		return NULL;
	}

	memset(_new, 0, sizeof(*_new));

	return _new;
}

static void sil_keyword_free(struct sil_keyword *kw)
{
	free(kw);
}

static struct sil_keyword *sil_keyword_new(char *keyword, int (*h)(void *))
{
	struct sil_keyword *kw;
	kw = sil_keyword_alloc();
	if (!kw) {
		SIL_LOG(NULL, 0, "sil_keyword_alloc err");
		return NULL;
	}

	kw->keyword = keyword;
	kw->handler = h;

	return kw;
}

static void sil_keyword_destroy(struct sil_keyword *kw)
{
	sil_keyword_free(kw);
}
