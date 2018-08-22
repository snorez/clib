#ifndef PLUGIN_H_AOWIFXRV
#define PLUGIN_H_AOWIFXRV

#ifdef __cplusplus
extern "C" {
#endif

#include <dlfcn.h>
#include "../include/clib_list.h"

struct clib_plugin {
	struct list_head	sibling;
	char			*path;
	void			*handle;

	char			*plugin_name;

	unsigned long		refcount;
};

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
extern int clib_plugin_add_needed(char *plugin_name, struct list_head *head);
extern int clib_plugin_remove_needed(char *plugin_name, struct list_head *head);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: PLUGIN_H_AOWIFXRV */
