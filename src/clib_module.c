/*
 * TODO
 * Copyright (C) 2018  zerons
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "../include/clib.h"

static LIST_HEAD(module_head);

static struct clib_module *clib_module_find_by_abspath(char *str)
{
	if (unlikely(!str)) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	struct clib_module *tmp;
	list_for_each_entry(tmp, &module_head, sibling) {
		if (!strcmp(tmp->path, str))
			return tmp;
	}
	return NULL;
}

/*
 * find module_name in loaded modules
 */
static struct clib_module *clib_module_find_by_modulename(const char *module_name)
{
	if (unlikely(!module_name)) {
		err_dbg(0, "arg check err");
		return NULL;
	}

	struct clib_module *tmp, *ret = NULL;
	size_t cnt = 0;
	list_for_each_entry(tmp, &module_head, sibling) {
		if (!tmp->module_name)
			continue;
		if (!strcmp(tmp->module_name, module_name)) {
			cnt++;
			ret = tmp;
		}
	}

	if (unlikely(cnt > 1)) {
		err_dbg(0, "multiple modules have the same name");
		return NULL;
	} else if (cnt == 1)
		return ret;
	else
		return NULL;
}

static struct clib_module *clib_module_new(char *path)
{
	struct clib_module *ret = NULL;

	ret = (struct clib_module *)malloc(sizeof(*ret));
	if (!ret) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));

	size_t pathlen = strlen(path) + 1;
	ret->path = (char *)malloc(pathlen);
	if (!ret) {
		err_dbg(0, "malloc err");
		free(ret);
		return NULL;
	}
	memcpy(ret->path, path, pathlen);

	ret->state = CLIB_MODULE_UNLOAD;
	INIT_LIST_HEAD(&ret->sibling);

	return ret;
}

static void clib_module_free(struct clib_module *cp)
{
	free(cp->path);
	free(cp);
}

static const char *module_entry_sym = "clib_module_init";
static const char *module_exit_sym = "clib_module_exit";
static const char *module_name_sym = "clib_module_name";
static const char *module_needed_sym = "clib_module_needed";
static char *clib_module_get_modulename(struct clib_module *cp)
{
	void *nameaddr = dlsym(cp->handle, module_name_sym);
	char *name = NULL;
	if (nameaddr && (name = (char *)nameaddr)) {
		return name;
	} else {
		cp->state = CLIB_MODULE_FORMAT_ERR;
		err_dbg(0, "dlsym or %s module format err", cp->path);
		return NULL;
	}
}

static int clib_module_check_needed(struct clib_module *p)
{
	struct clib_module *tmp;
	char **needed = dlsym(p->handle, module_needed_sym);
	if (!needed)
		return 0;
	for (int i = 0; needed[i]; i++) {
		tmp = clib_module_find_by_modulename(needed[i]);
		if (!tmp)
			return -1;
	}
	return 0;
}

static int clib_module_add_needed(char *module_name)
{
	struct clib_module *targetp = clib_module_find_by_modulename(module_name);
	if (!targetp) {
		err_dbg(0, "target module not loaded yet");
		return -1;
	}

	targetp->refcount++;
	return 0;
}

static int clib_module_remove_needed(char *module_name)
{
	struct clib_module *targetp = clib_module_find_by_modulename(module_name);
	if (!targetp) {
		err_dbg(0, "target module not loaded yet");
		return -1;
	}

	targetp->refcount--;
	return 0;
}

static int clib_module_handle_needed(struct clib_module *cp, int is_add)
{
	int err0 = 0, err1 = 0;
	char **needed = dlsym(cp->handle, module_needed_sym);
	if (!needed)
		return 0;

	int i = 0;
	for (i = 0; needed[i]; i++) {
		if (is_add) {
			err0 = clib_module_add_needed(needed[i]);
			if (err0) {
				err_dbg(0, "clib_module_add_needed err");
				break;
			}
		}
	}
	if (err0 || (!is_add)) {
		for (int j = 0; j < i; j++) {
			err1 = clib_module_remove_needed(needed[j]);
			if (err1) {
				err_dbg(0, "clib_module_remove_needed err");
				return -1;
			}
		}
	}
	if (err0)
		return -1;
	return 0;
}

static int clib_module_open(struct clib_module *cp)
{
	if (cp->state != CLIB_MODULE_UNLOAD)
		return 0;
	int flag = RTLD_NOW | RTLD_GLOBAL;
	cp->handle = dlopen(cp->path, flag);
	if (!cp->handle) {
		flag = RTLD_LAZY | RTLD_GLOBAL;
		cp->handle = dlopen(cp->path, flag);
	}
	if (!cp->handle) {
		err_dbg(0, "dlopen err: %s. maybe needed issues", dlerror());
		return -1;
	}

	int err = clib_module_check_needed(cp);
	if (err) {
		err_dbg(0, "needed issues");
		dlclose(cp->handle);
		cp->handle = NULL;
		return -1;
	}
	err = clib_module_handle_needed(cp, 1);
	if (err) {
		err_dbg(0, "add_needed err");
		dlclose(cp->handle);
		cp->handle = NULL;
		return -1;
	}
	cp->state = CLIB_MODULE_LOADED;
	cp->module_name = clib_module_get_modulename(cp);

	return 0;
}

static int clib_module_close(struct clib_module *cp, int force)
{
	if (cp->state == CLIB_MODULE_UNLOAD)
		return 0;

	int err = 0;
	if (!force) {
		err = clib_module_handle_needed(cp, 0);
		if (err == -1) {
			err_dbg(0, "remove_needed err");
			return -1;
		}
	}

	if (cp->handle)
		err = dlclose(cp->handle);
	if (err) {
		err_dbg(0, "dlclose err: %s", dlerror());
		return -1;
	}
	cp->handle = NULL;
	if (cp->state == CLIB_MODULE_LOADED)
		cp->state = CLIB_MODULE_UNLOAD;
	cp->module_name = NULL;
	return 0;
}

static int clib_module_do_entry(struct clib_module *cp, int argc, char *argv[])
{
	int err;
	if (cp->state == CLIB_MODULE_FORMAT_ERR)
		return -1;

	/*
	 * if old, that means a same name module has been loaded
	 * if !old, that means no other loaded module using this name
	 */
	struct clib_module *old = clib_module_find_by_modulename(cp->module_name);
	if (IS_ERR(old)) {
		err_dbg(0, "module_name already used by %s",
				old->path);
		return -1;
	} else if (old == cp) {
		/* XXX, we are sure this is the first time load this module */
	} else if (old) {
		cp->state = CLIB_MODULE_FORMAT_ERR;
		return -1;
	}

	void *addr = dlsym(cp->handle, module_entry_sym);
	if (!addr) {
		cp->state = CLIB_MODULE_FORMAT_ERR;
		err_dbg(0, "dlsym err: %s", dlerror());
		return -1;
	}

	int (*entry)(struct clib_module *cp, int argc, char **argv) =
		(int (*)(struct clib_module *, int argc, char **))addr;
	err = entry(cp, argc, argv);
	if (err) {
		err_dbg(0, "module entry return err");
		return -1;
	}

	return 0;
}

static int clib_module_do_exit(struct clib_module *cp)
{
	if (cp->state != CLIB_MODULE_LOADED)
		return 0;
	void *addr = dlsym(cp->handle, module_exit_sym);
	if (!addr) {
		cp->state = CLIB_MODULE_FORMAT_ERR;
		return -1;
	}
	void (*exithandler)(void) = (void (*)(void))addr;
	exithandler();
	return 0;
}

/*
 * @argv: [0] module id or path
 *	  [...] args of modules
 * check if argv[0] is existed in head
 * if not existed, alloc a new one, check the module_name(TODO) again
 */
int clib_module_load(int argc, char *argv[])
{
	int err;
	if ((argc < 1) || (argv[0][0] != '/')) {
		err_dbg(0, "args invalid");
		return -1;
	}

	struct clib_module *old = clib_module_find_by_abspath(argv[0]);
	if (old) {
		if (old->state == CLIB_MODULE_LOADED) {
			err_dbg(0, "module has been loaded");
			return 0;
		} else if (old->state == CLIB_MODULE_FORMAT_ERR) {
			err_dbg(0, "module can not be loaded");
			return 0;
		}

		err = clib_module_open(old);
		if (err) {
			err_dbg(0, "clib_module_open err");
			return -1;
		}

		err = clib_module_do_entry(old, argc-1, &argv[1]);
		if (err) {
			err_dbg(0, "clib_module_do_entry err");
			clib_module_close(old, 0);
			return -1;
		}
		return 0;
	}

	struct clib_module *newp = clib_module_new(argv[0]);
	if (!newp) {
		err_dbg(0, "clib_module_new err");
		return -1;
	}

	err = clib_module_open(newp);
	if (err) {
		err_dbg(0, "clib_module_open err");
		clib_module_free(newp);
		return -1;
	}

	err = clib_module_do_entry(newp, argc-1, &argv[1]);
	if (err) {
		clib_module_close(newp, 0);
		clib_module_free(newp);
		err_dbg(0, "clib_module_do_entry err");
		return -1;
	}
	list_add_tail(&newp->sibling, &module_head);
	return 0;
}

int clib_module_unload(int argc, char *argv[])
{
	int err;
	if (argc < 1) {
		err_dbg(0, "args invalid");
		return -1;
	}

	struct clib_module *target = clib_module_find_by_abspath(argv[0]);
	if (target)
		goto found;

	target = clib_module_find_by_modulename(argv[0]);
	if (!target) {
		err_dbg(0, "module %s not found", argv[0]);
		return -1;
	}

found:
	if (target->state != CLIB_MODULE_LOADED) {
		return 0;
	}
	if (target->refcount) {
		err_dbg(0, "module %s in use", target->path);
		return -1;
	}
	err = clib_module_do_exit(target);
	if (err) {
		err_dbg(0, "clib_module_do_exit err");
		/* do not return now, clean the module */
	}
	err = clib_module_close(target, 0);
	if (err) {
		err_dbg(0, "clib_module_close err");
		return -1;
	}
	return 0;
}

int clib_module_reload(int argc, char *argv[])
{
	int err;
	if (argc < 1) {
		err_dbg(0, "args invalid");
		return -1;
	}

	/* check if argv[0] is a module_name */
	struct clib_module *old = clib_module_find_by_modulename(argv[0]);
	char *arg0 = NULL;
	if (old) {
		arg0 = malloc(strlen(old->path) + 1);
		if (!arg0) {
			err_dbg(0, "malloc err");
			return -1;
		}
		memcpy(arg0, old->path, strlen(old->path)+1);
		argv[0] = arg0;
	}

	err = clib_module_unload(1, argv);
	if (err) {
		err_dbg(0, "clib_module_unload err");
		goto out;
	}

	err = clib_module_load(argc, argv);
	if (err) {
		err_dbg(0, "clib_module_load err");
		goto out;
	}

out:
	if (arg0)
		free(arg0);
	return err;
}

void clib_module_cleanup(void)
{
	struct clib_module *tmp, *next;
	int err;
	list_for_each_entry_safe(tmp, next, &module_head, sibling) {
		clib_module_do_exit(tmp);
		err = clib_module_close(tmp, 1);
		if (err)
			err_dbg(0, "clib_module_close %s err", tmp->path);
		list_del_init(&tmp->sibling);
		clib_module_free(tmp);
	}
	return;
}

static char *get_state_string(enum clib_module_state state)
{
	switch (state) {
	case CLIB_MODULE_UNLOAD:
		return "unload";
	case CLIB_MODULE_LOADED:
		return "loaded";
	case CLIB_MODULE_FORMAT_ERR:
		return "format err";
	default:
		return NULL;
	}
}
void clib_module_print()
{
	struct clib_module *tmp;
	int i = 0;
	list_for_each_entry(tmp, &module_head, sibling) {
		fprintf(stdout, "%d\t%ld\t%s\t\t%s\n>>>> %s\t\n",
				i++,
				tmp->refcount,
				get_state_string(tmp->state),
				tmp->module_name,
				tmp->path);
	}
}

struct list_head *clib_module_get_head(void)
{
	return &module_head;
}

long clib_module_call_func(const char *module_name, const char *func_name,
			   int argc, ...)
{
	if (argc > CALL_FUNC_MAX_ARGS) {
		err_dbg(0, "argc too many");
		return -1;
	}

	struct clib_module *cp = clib_module_find_by_modulename(module_name);
	if (!cp) {
		err_dbg(0, "%s not loaded yet", module_name);
		return -1;
	}

	void *addr = dlsym(cp->handle, func_name);
	if (!addr) {
		err_dbg(0, "%s not found in %s", func_name, module_name);
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
		long (*func_addr)(long,long,long,long,long,long,long,long,long);
		func_addr = addr;
		err = func_addr(arg[0], arg[1], arg[2], arg[3],
				arg[4], arg[5], arg[6], arg[7], arg[8]);
		break;
	}
	default:
	{
		err = -1;
		break;
	}
	}

	va_end(va);
	return err;
}
