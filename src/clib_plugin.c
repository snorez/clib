#include "../include/clib_plugin.h"
struct clib_plugin *clib_plugin_find_by_id_path(char *str, struct list_head *head)
{
	int use_id = 0;
	int id = 0;
	int found = 0;

	id = atoi(str);
	if (id)
		use_id = 1;
	else if ((str[0] == '0') && (str[1] == 0))
		use_id = 1;

	struct clib_plugin *tmp;
	list_for_each_entry(tmp, head, sibling) {
		if (use_id) {
			if (!id) {
				found = 1;
				break;
			}
			id--;
		} else {
			if ((!memcmp(tmp->path, str, strlen(str)+1))) {
				found = 1;
				break;
			}
		}
	}

	if (found)
		return tmp;
	else
		return NULL;
}

struct clib_plugin *clib_plugin_alloc(char *path)
{
	struct clib_plugin *ret = NULL;

	ret = (struct clib_plugin *)malloc(sizeof(*ret));
	if (!ret) {
		err_msg(err_fmt("malloc err"));
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));

	size_t pathlen = strlen(path) + 1;
	ret->path = (char *)malloc(pathlen);
	if (!ret) {
		err_msg(err_fmt("malloc err"));
		free(ret);
		return NULL;
	}
	memcpy(ret->path, path, pathlen);

	return ret;
}

void clib_plugin_free(struct clib_plugin *cp)
{
	free(cp->path);
	free(cp);
}

void clib_plugin_insert(struct clib_plugin *cp, struct list_head *head)
{
	list_add_tail(&cp->sibling, head);
}

void clib_plugin_remove(struct clib_plugin *cp)
{
	list_del(&cp->sibling);
}

int clib_plugin_open(struct clib_plugin *cp)
{
	int flag = RTLD_NOW | RTLD_GLOBAL;
	cp->handle = dlopen(cp->path, flag);
	if (!cp->handle) {
		err_msg(err_fmt("dlopen err: %s"), dlerror());
		return -1;
	}
	return 0;
}

int clib_plugin_close(struct clib_plugin *cp)
{
	int err = dlclose(cp->handle);
	if (err) {
		err_msg(err_fmt("dlclose err: %s"), dlerror());
		return -1;
	}
	return 0;
}

static const char *plugin_entry_sym = "clib_plugin_init";
static const char *plugin_exit_sym = "clib_plugin_exit";
static const char *plugin_name_sym = "clib_plugin_name";
int clib_plugin_do_entry(struct clib_plugin *cp, int argc, char *argv[],
			 struct list_head *head)
{
	void *nameaddr = dlsym(cp->handle, plugin_name_sym);
	char *name = NULL;
	if (nameaddr && (name = *(char **)nameaddr)) {
		struct clib_plugin *old =
				clib_plugin_find_by_pluginname(name, head);
		if (old) {
			err_dbg(0, err_fmt("plugin_name already used by %s"),
					old->path);
			return -1;
		} else
			cp->plugin_name = name;
	}

	void *addr = dlsym(cp->handle, plugin_entry_sym);
	if (!addr) {
		err_msg(err_fmt("dlsym err: %s"), dlerror());
		return -1;
	}

	int (*entry)(struct clib_plugin *cp, int argc, char **argv) =
		(int (*)(struct clib_plugin *, int argc, char **))addr;
	return entry(cp, argc, argv);
}

void clib_plugin_do_exit(struct clib_plugin *cp)
{
	void *addr = dlsym(cp->handle, plugin_exit_sym);
	if (!addr)
		return;
	void (*exithandler)(void) = (void (*)(void))addr;
	exithandler();
}

struct clib_plugin *clib_plugin_find_by_pluginname(char *plugin_name,
							struct list_head *head)
{
	if (!plugin_name)
		return NULL;

	struct clib_plugin *tmp;
	list_for_each_entry(tmp, head, sibling) {
		if (!tmp->plugin_name)
			continue;
		if (!memcmp(tmp->plugin_name, plugin_name, strlen(plugin_name)+1))
			return tmp;
	}
	return NULL;
}

int clib_plugin_add_needed(char *plugin_name, struct list_head *head)
{
	struct clib_plugin *targetp = clib_plugin_find_by_pluginname(plugin_name,
								     head);
	if (!targetp) {
		err_dbg(0, err_fmt("target plugin not loaded yet"));
		return -1;
	}

	targetp->refcount++;
	return 0;
}

int clib_plugin_remove_needed(char *plugin_name, struct list_head *head)
{
	struct clib_plugin *targetp = clib_plugin_find_by_pluginname(plugin_name,
								     head);
	if (!targetp) {
		err_dbg(0, err_fmt("target plugin not loaded yet"));
		return -1;
	}

	targetp->refcount--;
	return 0;
}
