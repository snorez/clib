#ifndef PLUGIN_H_AOWIFXRV
#define PLUGIN_H_AOWIFXRV

#include "../include/clib_utils.h"
#include "../include/clib_list.h"
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>

DECL_BEGIN

enum clib_plugin_state {
	CLIB_PLUGIN_UNLOAD,	/* set when close */
	CLIB_PLUGIN_LOADED,	/* set when open */
	CLIB_PLUGIN_FORMAT_ERR,	/* set when sym not found */
};
struct clib_plugin {
	struct list_head	sibling;
	char			*path;	/* could be absolute path or relative path */
	void			*handle;

	/* set by plugin itself, find by dlsym plugin_name_sym */
	char			*plugin_name;

	/* if not 0, reload/unload should take care of */
	unsigned long		refcount;
	enum clib_plugin_state	state;
};

#define	CLIB_PLUGIN_INIT()	\
C_SYM int clib_plugin_init(struct clib_plugin *cp, int argc, char *argv[])

#define	CLIB_PLUGIN_EXIT()	\
C_SYM void clib_plugin_exit(void)

#define	CLIB_PLUGIN_NAME(x)	\
char clib_plugin_name[] = x

#define	CLIB_PLUGIN_NEEDED0()	\
const char *clib_plugin_needed[] = {NULL}
#define	CLIB_PLUGIN_NEEDED1(x)	\
const char *clib_plugin_needed[] = {x, NULL}
#define	CLIB_PLUGIN_NEEDED2(x0, x1)	\
const char *clib_plugin_needed[] = {x0, x1, NULL}
#define	CLIB_PLUGIN_NEEDED3(x0, x1, x2)	\
const char *clib_plugin_needed[] = {x0, x1, x2, NULL}
#define	CLIB_PLUGIN_NEEDED4(x0, x1, x2, x3)	\
const char *clib_plugin_needed[] = {x0, x1, x2, x3, NULL}
#define	CLIB_PLUGIN_NEEDED5(x0, x1, x2, x3, x4)	\
const char *clib_plugin_needed[] = {x0, x1, x2, x3, x4, NULL}
#define	CLIB_PLUGIN_NEEDED6(x0, x1, x2, x3, x4, x5)	\
const char *clib_plugin_needed[] = {x0, x1, x2, x3, x4, x5, NULL}

#if 0
extern struct clib_plugin *clib_plugin_find_by_id_path(char *str,
							struct list_head *head);
extern struct clib_plugin *clib_plugin_alloc(char *path);
extern void clib_plugin_free(struct clib_plugin *cp);
extern void clib_plugin_insert(struct clib_plugin *cp, struct list_head *head);
extern void clib_plugin_remove(struct clib_plugin *cp);
extern int clib_plugin_open(struct clib_plugin *cp);
extern int clib_plugin_close(struct clib_plugin *cp);
extern int clib_plugin_do_entry(struct clib_plugin *cp, int argc, char **argv,
				struct list_head *head);
extern void clib_plugin_do_exit(struct clib_plugin *cp);
extern struct clib_plugin *clib_plugin_find_by_pluginname(char *plugin_name,
							  struct list_head *head);
#endif
extern int clib_plugin_load(int argc, char *argv[], struct list_head *head);
extern int clib_plugin_unload(int argc, char *argv[], struct list_head *head);
extern int clib_plugin_reload(int argc, char *argv[], struct list_head *head);
extern int clib_plugin_init_root(const char *dir, struct list_head *head);
extern void clib_plugin_cleanup(struct list_head *head);
extern void clib_plugin_print(struct list_head *head);

DECL_END

#endif /* end of include guard: PLUGIN_H_AOWIFXRV */
