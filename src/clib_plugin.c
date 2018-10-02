#include "../include/clib.h"

static LIST_HEAD(plugin_head);
static lock_t plugin_head_lock;

static struct clib_plugin *clib_plugin_find_by_id_path(char *str,
							struct list_head *head)
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
			if ((!strcmp(tmp->path, str))) {
				found = 1;
				break;
			}
		}
	}

	if (found)
		return tmp;
	if (use_id)
		return ERR_PTR(-EINVAL);
	return NULL;
}

/*
 * find plugin_name in loaded plugins
 */
static struct clib_plugin *clib_plugin_find_by_pluginname(const char *plugin_name,
							struct list_head *head)
{
	if (!plugin_name)
		return NULL;

	struct clib_plugin *tmp, *ret = NULL;
	size_t cnt = 0;
	list_for_each_entry(tmp, head, sibling) {
		if (!tmp->plugin_name)
			continue;
		if (!strcmp(tmp->plugin_name, plugin_name)) {
			cnt++;
			ret = tmp;
		}
	}

	if (cnt > 1)
		return ERR_PTR(-EEXIST);
	else if (cnt == 1)
		return ret;
	else
		return NULL;
}

static struct clib_plugin *clib_plugin_alloc(char *path)
{
	struct clib_plugin *ret = NULL;

	ret = (struct clib_plugin *)malloc(sizeof(*ret));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));

	size_t pathlen = strlen(path) + 1;
	ret->path = (char *)malloc(pathlen);
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		free(ret);
		return NULL;
	}
	memcpy(ret->path, path, pathlen);

	ret->state = CLIB_PLUGIN_UNLOAD;
	INIT_LIST_HEAD(&ret->sibling);

	return ret;
}

static void clib_plugin_free(struct clib_plugin *cp)
{
	free(cp->path);
	free(cp);
}

static void clib_plugin_insert(struct clib_plugin *cp, struct list_head *head)
{
	list_add_tail(&cp->sibling, head);
}

static void clib_plugin_remove(struct clib_plugin *cp)
{
	list_del_init(&cp->sibling);
}

static const char *plugin_entry_sym = "clib_plugin_init";
static const char *plugin_exit_sym = "clib_plugin_exit";
static const char *plugin_name_sym = "clib_plugin_name";
static const char *plugin_needed_sym = "clib_plugin_needed";
static char *clib_plugin_get_pluginname(struct clib_plugin *cp)
{
	void *nameaddr = dlsym(cp->handle, plugin_name_sym);
	char *name = NULL;
	if (nameaddr && (name = (char *)nameaddr)) {
		return name;
	} else {
		cp->state = CLIB_PLUGIN_FORMAT_ERR;
		err_dbg(0, err_fmt("dlsym or %s plugin format err"), cp->path);
		return NULL;
	}
}

static int clib_plugin_check_needed(struct clib_plugin *p,
					  struct list_head *head)
{
	struct clib_plugin *tmp;
	char **needed = dlsym(p->handle, plugin_needed_sym);
	if (!needed)
		return 0;
	for (int i = 0; needed[i]; i++) {
		tmp = clib_plugin_find_by_pluginname(needed[i], head);
		if (!tmp)
			return -1;
	}
	return 0;
}

/*
 * clib_plugin_*_needed called by plugin, not main routine
 */
static int clib_plugin_add_needed(char *plugin_name, struct list_head *head)
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

static int clib_plugin_remove_needed(char *plugin_name, struct list_head *head)
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

static int clib_plugin_handle_needed(struct clib_plugin *cp,
					   struct list_head *head,
					   int is_add)
{
	int err0 = 0, err1 = 0;
	char **needed = dlsym(cp->handle, plugin_needed_sym);
	if (!needed)
		return 0;

	int i = 0;
	for (i = 0; needed[i]; i++) {
		if (is_add) {
			err0 = clib_plugin_add_needed(needed[i], head);
			if (err0) {
				err_dbg(0, err_fmt("clib_plugin_add_needed err"));
				break;
			}
		}
	}
	if (err0 || (!is_add)) {
		for (int j = 0; j < i; j++) {
			err1 = clib_plugin_remove_needed(needed[j], head);
			if (err1) {
				err_dbg(0, err_fmt("clib_plugin_remove_needed err"));
				return -1;
			}
		}
	}
	if (err0)
		return -1;
	return 0;
}

static int clib_plugin_open(struct clib_plugin *cp, struct list_head *head)
{
	if (cp->state != CLIB_PLUGIN_UNLOAD)
		return 0;
	int flag = RTLD_NOW | RTLD_GLOBAL;
	cp->handle = dlopen(cp->path, flag);
	if (!cp->handle) {
		err_dbg(0, err_fmt("dlopen err: %s. maybe needed issues"),
					dlerror());
		return -1;
	}

	int err = clib_plugin_check_needed(cp, head);
	if (err) {
		err_dbg(0, err_fmt("needed issues"));
		dlclose(cp->handle);
		cp->handle = NULL;
		return -1;
	}
	err = clib_plugin_handle_needed(cp, head, 1);
	if (err) {
		err_dbg(0, err_fmt("add_needed err"));
		dlclose(cp->handle);
		cp->handle = NULL;
		return -1;
	}
	cp->state = CLIB_PLUGIN_LOADED;
	cp->plugin_name = clib_plugin_get_pluginname(cp);

	return 0;
}

static int clib_plugin_close(struct clib_plugin *cp, struct list_head *head,
			     int force)
{
	if (cp->state == CLIB_PLUGIN_UNLOAD)
		return 0;

	int err = 0;
	if (!force) {
		err = clib_plugin_handle_needed(cp, head, 0);
		if (err == -1) {
			err_dbg(0, err_fmt("remove_needed err"));
			return -1;
		}
	}

	if (cp->handle)
		err = dlclose(cp->handle);
	if (err) {
		err_dbg(0, err_fmt("dlclose err: %s"), dlerror());
		return -1;
	}
	cp->handle = NULL;
	if (cp->state == CLIB_PLUGIN_LOADED)
		cp->state = CLIB_PLUGIN_UNLOAD;
	cp->plugin_name = NULL;
	return 0;
}

static int clib_plugin_do_entry(struct clib_plugin *cp, int argc, char *argv[],
				struct list_head *head)
{
	int err;
	if (cp->state == CLIB_PLUGIN_FORMAT_ERR)
		return -1;

	/*
	 * if old, that means a same name plugin has been loaded
	 * if !old, that means no other loaded plugin using this name
	 */
	struct clib_plugin *old = clib_plugin_find_by_pluginname(
						cp->plugin_name, head);
	if (IS_ERR(old)) {
		err_dbg(0, err_fmt("plugin_name already used by %s"),
				old->path);
		return -EEXIST;
	} else if (old == cp) {
		/* XXX, we are sure this is the first time load this plugin */
	} else if (old) {
		cp->state = CLIB_PLUGIN_FORMAT_ERR;
		return -EINVAL;
	}

	void *addr = dlsym(cp->handle, plugin_entry_sym);
	if (!addr) {
		cp->state = CLIB_PLUGIN_FORMAT_ERR;
		err_dbg(0, err_fmt("dlsym err: %s"), dlerror());
		return -EINVAL;
	}

	int (*entry)(struct clib_plugin *cp, int argc, char **argv) =
		(int (*)(struct clib_plugin *, int argc, char **))addr;
	err = entry(cp, argc, argv);
	if (err) {
		err_dbg(0, err_fmt("plugin entry return err"));
		return -EINVAL;
	}

	return 0;
}

static int clib_plugin_do_exit(struct clib_plugin *cp)
{
	if (cp->state != CLIB_PLUGIN_LOADED)
		return 0;
	void *addr = dlsym(cp->handle, plugin_exit_sym);
	if (!addr) {
		cp->state = CLIB_PLUGIN_FORMAT_ERR;
		return -1;
	}
	void (*exithandler)(void) = (void (*)(void))addr;
	exithandler();
	return 0;
}

/*
 * @argv: [0] plugin id or path
 *	  [...] args of plugins
 * check if argv[0] is existed in head
 * if not existed, alloc a new one, check the plugin_name(TODO) again
 */
int clib_plugin_load(int argc, char *argv[])
{
	struct list_head *head = &plugin_head;
	int err;
	if (argc < 1) {
		err_dbg(0, err_fmt("argc invalid"));
		return -1;
	}

	/* First, find by id or path */
	mutex_lock(&plugin_head_lock);
	struct clib_plugin *old = clib_plugin_find_by_id_path(argv[0], head);
	if (old) {
		if (old->state == CLIB_PLUGIN_LOADED) {
			err_dbg(0, err_fmt("plugin has been loaded"));
			mutex_unlock(&plugin_head_lock);
			return 0;
		} else if (old->state == CLIB_PLUGIN_FORMAT_ERR) {
			err_dbg(0, err_fmt("plugin can not be loaded"));
			mutex_unlock(&plugin_head_lock);
			return 0;
		}

		err = clib_plugin_open(old, head);
		if (err) {
			err_dbg(0, err_fmt("clib_plugin_open err"));
			mutex_unlock(&plugin_head_lock);
			return -1;
		}

		err = clib_plugin_do_entry(old, argc-1, &argv[1], head);
		if (err) {
			err_dbg(0, err_fmt("clib_plugin_do_entry err"));
			clib_plugin_close(old, head, 0);
			mutex_unlock(&plugin_head_lock);
			return -1;
		}
		mutex_unlock(&plugin_head_lock);
		return 0;
	} else if (IS_ERR(old)) {
		err_dbg(0, err_fmt("clib_plugin_find_by_id_path err"));
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	/* argv[0] is not a module in init_dir */
	struct clib_plugin *newp = clib_plugin_alloc(argv[0]);
	if (!newp) {
		err_dbg(0, err_fmt("clib_plugin_alloc err"));
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	err = clib_plugin_open(newp, head);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_open err"));
		clib_plugin_free(newp);
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	err = clib_plugin_do_entry(newp, argc-1, &argv[1], head);
	if (err) {
		clib_plugin_close(newp, head, 0);
		clib_plugin_free(newp);
		err_dbg1(err, err_fmt("clib_plugin_do_entry err"));
		mutex_unlock(&plugin_head_lock);
		return -1;
	}
	clib_plugin_insert(newp, head);
	mutex_unlock(&plugin_head_lock);
	return 0;
}

int clib_plugin_unload(int argc, char *argv[])
{
	struct list_head *head = &plugin_head;
	int err;
	if (argc != 1) {
		err_dbg(0, err_fmt("argc invalid"));
		return -1;
	}

	mutex_lock(&plugin_head_lock);
	struct clib_plugin *target = clib_plugin_find_by_id_path(argv[0], head);
	if (target) {
		goto found;
	} else if (IS_ERR(target)) {
		err_dbg(0, err_fmt("clib_plugin_find_by_id_path err"));
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	target = clib_plugin_find_by_pluginname(argv[0], head);
	if (!target) {
		err_dbg(0, err_fmt("plugin %s not found"), argv[0]);
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

found:
	if (target->state != CLIB_PLUGIN_LOADED) {
		mutex_unlock(&plugin_head_lock);
		return 0;
	}
	if (target->refcount) {
		err_dbg(0, err_fmt("plugin %s in use"), target->path);
		mutex_unlock(&plugin_head_lock);
		return -1;
	}
	err = clib_plugin_do_exit(target);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_do_exit err"));
		/* do not return now, clean the plugin */
	}
	err = clib_plugin_close(target, head, 0);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_close err"));
		mutex_unlock(&plugin_head_lock);
		return -1;
	}
	mutex_unlock(&plugin_head_lock);
	return 0;
}

int clib_plugin_reload(int argc, char *argv[])
{
	struct list_head *head = &plugin_head;
	int err;
	if (argc < 1) {
		err_dbg(0, err_fmt("argc invalid"));
		return -1;
	}

	mutex_lock(&plugin_head_lock);
	/* check if argv[0] is a plugin_name */
	struct clib_plugin *old = clib_plugin_find_by_pluginname(argv[0], head);
	char *arg0 = NULL;
	if (old) {
		arg0 = malloc(strlen(old->path) + 1);
		if (!arg0) {
			err_dbg(0, err_fmt("malloc err"));
			mutex_unlock(&plugin_head_lock);
			return -1;
		}
		memcpy(arg0, old->path, strlen(old->path)+1);
		argv[0] = arg0;
	}
	mutex_unlock(&plugin_head_lock);

	err = clib_plugin_unload(1, argv);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_unload err"));
		goto out;
	}

	err = clib_plugin_load(argc, argv);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_load err"));
		goto out;
	}

out:
	if (arg0)
		free(arg0);
	return err;
}

#define	FULL_PATH_MAX	4096
#define	FULL_PATH_RESERVE	0x10
static char root_path[FULL_PATH_MAX];
int clib_plugin_init_root(const char *dir)
{
	struct list_head *head = &plugin_head;
	if (*dir != '/') {
		err_dbg(0, err_fmt("dir must be absolute path"));
		return -1;
	}
	if (strlen(dir) >= (FULL_PATH_MAX-FULL_PATH_RESERVE)) {
		err_dbg(0, err_fmt("dir name too long"));
		return -1;
	}

	DIR *root = opendir(dir);
	if (!root) {
		err_dbg(1, err_fmt("opendir err"));
		return -1;
	}

	struct dirent *dp;
	char full_path[FULL_PATH_MAX];
	memset(root_path, 0, FULL_PATH_MAX);
	memset(full_path, 0, FULL_PATH_MAX);
	memcpy(root_path, dir, strlen(dir));
	if (root_path[strlen(root_path)-1] != '/')
		root_path[strlen(dir)] = '/';
	memcpy(full_path, root_path, strlen(root_path));
	size_t base_len = strlen(full_path);

	mutex_lock(&plugin_head_lock);
	while ((dp = readdir(root))) {
		if (dp->d_type != DT_REG)
			continue;
		if (strlen(dp->d_name) < 4)
			continue;
		if (strcmp(&dp->d_name[strlen(dp->d_name)-3], ".so"))
			continue;
		memset(full_path+base_len, 0, FULL_PATH_MAX-base_len);
		memcpy(full_path+base_len, dp->d_name, strlen(dp->d_name));
		if (clib_plugin_find_by_id_path(full_path, head))
			continue;
		struct clib_plugin *newp = clib_plugin_alloc(full_path);
		if (!newp) {
			err_dbg(0, err_fmt("clib_plugin_alloc err"));
			closedir(root);
			mutex_unlock(&plugin_head_lock);
			return -1;
		}
		clib_plugin_insert(newp, head);
	}
	mutex_unlock(&plugin_head_lock);

	closedir(root);
	return 0;
}

/* this should called after init_root */
int clib_plugin_load_default(struct clib_plugin_load_arg *s, int cnt)
{
	char abs_path[FULL_PATH_MAX];
	int i = 0;
	int err = 0;
	for (i = 0; i < cnt; i++) {
		memset(abs_path, 0, FULL_PATH_MAX);
		snprintf(abs_path, FULL_PATH_MAX-1, "%s%s.so",
					root_path, s[i].so_name);
		s[i].argv[0] = abs_path;
		s[i].argv[s[i].argc] = NULL;
		err = clib_plugin_load(s[i].argc, s[i].argv);
		if (err == -1) {
			err_dbg(0, err_fmt("clib_plugin_load %s err"), abs_path);
			return -1;
		}
	}
	return 0;
}

void clib_plugin_cleanup(void)
{
	struct list_head *head = &plugin_head;
	struct clib_plugin *tmp, *next;
	int err;
	mutex_lock(&plugin_head_lock);
	list_for_each_entry_safe(tmp, next, head, sibling) {
		clib_plugin_do_exit(tmp);
		err = clib_plugin_close(tmp, head, 1);
		if (err)
			err_dbg(0, err_fmt("clib_plugin_close %s err"), tmp->path);
		clib_plugin_remove(tmp);
		clib_plugin_free(tmp);
	}
	mutex_unlock(&plugin_head_lock);
	return;
}

static char *get_state_string(enum clib_plugin_state state)
{
	switch (state) {
	case CLIB_PLUGIN_UNLOAD:
		return "unload";
	case CLIB_PLUGIN_LOADED:
		return "loaded";
	case CLIB_PLUGIN_FORMAT_ERR:
		return "format err";
	default:
		return NULL;
	}
}
void clib_plugin_print()
{
	struct list_head *head = &plugin_head;
	struct clib_plugin *tmp;
	int i = 0;
	mutex_lock(&plugin_head_lock);
	list_for_each_entry(tmp, head, sibling) {
		fprintf(stdout, "%d\t%ld\t%s\t\t%s\n\t%s\t\n",
				i++,
				tmp->refcount,
				get_state_string(tmp->state),
				tmp->plugin_name,
				tmp->path);
	}
	mutex_unlock(&plugin_head_lock);
}

struct list_head *clib_plugin_get_head(void)
{
	return &plugin_head;
}

long clib_plugin_call_func(const char *plugin_name, const char *func_name,
			   int argc, ...)
{
	if (argc > CALL_FUNC_MAX_ARGS) {
		err_dbg(0, err_fmt("argc too many"));
		return -1;
	}

	mutex_lock(&plugin_head_lock);
	struct list_head *head = &plugin_head;
	struct clib_plugin *cp = clib_plugin_find_by_pluginname(plugin_name, head);
	if (!cp) {
		err_dbg(0, err_fmt("%s not loaded yet"), plugin_name);
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	void *addr = dlsym(cp->handle, func_name);
	if (!addr) {
		err_dbg(0, err_fmt("%s not found in %s"), func_name, plugin_name);
		mutex_unlock(&plugin_head_lock);
		return -1;
	}

	va_list va;
	long err;
	va_start(va, argc);
	long arg[argc];
	for (int i = 0; i < argc; i++) {
		arg[i] = va_arg(va, long);
	}

	switch (argc) {
	case 0:
	{
		long (*func_addr)(void);
		func_addr = addr;
		err = func_addr();
		break;
	}
	case 1:
	{
		long (*func_addr)(long);
		func_addr = addr;
		err = func_addr(arg[0]);
		break;
	}
	case 2:
	{
		long (*func_addr)(long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1]);
		break;
	}
	case 3:
	{
		long (*func_addr)(long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2]);
		break;
	}
	case 4:
	{
		long (*func_addr)(long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3]);
		break;
	}
	case 5:
	{
		long (*func_addr)(long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3], arg[4]);
		break;
	}
	case 6:
	{
		long (*func_addr)(long,long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
		break;
	}
	case 7:
	{
		long (*func_addr)(long,long,long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3],
				arg[4], arg[5], arg[6]);
		break;
	}
	case 8:
	{
		long (*func_addr)(long,long,long,long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3],
				arg[4], arg[5], arg[6], arg[7]);
		break;
	}
	case 9:
	{
		long (*func_addr)(long,long,long,long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3],
				arg[4], arg[5], arg[6], arg[7]);
		break;
	}
	default:
		BUG();
	}

	va_end(va);
	mutex_unlock(&plugin_head_lock);
	return err;
}

int clib_cmd_plugin_setup(struct clib_cmd *cs, int cs_cnt, char *plugin_root,
				 struct clib_plugin_load_arg *defplugin,
				 size_t plugin_cnt)
{
	int err = 0;
	err = clib_cmd_add_array(cs, cs_cnt);
	if (err) {
		err_dbg(0, err_fmt("clib_cmd_add_array err"));
		return -1;
	}

	err = clib_plugin_init_root(plugin_root);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_init_root err"));
		return -1;
	}

	err = clib_plugin_load_default(defplugin, plugin_cnt);
	if (err) {
		err_dbg(0, err_fmt("clib_plugin_load_default err"));
		return -1;
	}

	clib_set_cmd_completor();

	return 0;
}
