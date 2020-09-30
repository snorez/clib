#include "./testsuite.h"

static struct slist_head this_head;
static unsigned this_slist_id = 0;

struct this_slist {
	int			id;
	struct slist_head	sibling;
};

static struct this_slist *this_slist_alloc(void)
{
	struct this_slist *_new;
	_new = (struct this_slist *)malloc(sizeof(*_new));
	_new->id = this_slist_id;
	this_slist_id++;
	return _new;
}

static void this_slist_iter(void)
{
	ts_output(1, stdout, "Iterating slist\n");
	struct this_slist *e;
	slist_for_each_entry(e, &this_head, sibling) {
		ts_output(1, stdout, "%d\n", e->id);
	}

	return;
}

static void this_slist_insert(struct this_slist *e, int tail)
{
	ts_output(1, stdout, "Add #%d slist into head\n", e->id);
	if (!tail)
		slist_add(&e->sibling, &this_head);
	else
		slist_add_tail(&e->sibling, &this_head);

	return;
}

static void this_slist_destroy(void)
{
	struct this_slist *cur, *next;
	slist_for_each_entry_safe(cur, next, &this_head, sibling) {
		slist_del(&cur->sibling, &this_head);
		free(cur);
	}
}

void test_slist(void)
{
	ts_output(1, stdout, "Init slist head\n");
	INIT_SLIST_HEAD(&this_head);

	struct this_slist *e;
	e = this_slist_alloc();
	this_slist_insert(e, 0);

	this_slist_iter();

	e = this_slist_alloc();
	this_slist_insert(e, 1);

	this_slist_iter();

	this_slist_destroy();

	return;
}
