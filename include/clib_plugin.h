#ifndef PLUGIN_H_AOWIFXRV
#define PLUGIN_H_AOWIFXRV

#include "../include/clib_utils.h"
#include "../include/clib_list.h"
#include "../include/clib_cmd.h"
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

struct clib_plugin_load_arg {
	char			*so_name;		/* exclude .so */
	int			argc;
	char			*argv[CMD_ARGS_MAX];	/* argv[0] will be reset */
};
#define	CLIB_PLUGIN_LOAD_ARG1(plugin_name) \
{#plugin_name, 1, {NULL}}

#define	CLIB_PLUGIN_INIT()	\
C_SYM int clib_plugin_init(struct clib_plugin *cp, int argc, char *argv[])

#define	CLIB_PLUGIN_EXIT()	\
C_SYM void clib_plugin_exit(void)

#define	CLIB_PLUGIN_NAME(x)	\
char clib_plugin_name[] = #x

#define	CLIB_PLUGIN_NEEDED0()	\
const char *clib_plugin_needed[] = {NULL}
#define	CLIB_PLUGIN_NEEDED1(x)	\
const char *clib_plugin_needed[] = {#x, NULL}
#define	CLIB_PLUGIN_NEEDED2(x0, x1)	\
const char *clib_plugin_needed[] = {#x0, #x1, NULL}
#define	CLIB_PLUGIN_NEEDED3(x0, x1, x2)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, NULL}
#define	CLIB_PLUGIN_NEEDED4(x0, x1, x2, x3)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, NULL}
#define	CLIB_PLUGIN_NEEDED5(x0, x1, x2, x3, x4)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, #x4, NULL}
#define	CLIB_PLUGIN_NEEDED6(x0, x1, x2, x3, x4, x5)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, NULL}
#define	CLIB_PLUGIN_NEEDED7(x0, x1, x2, x3, x4, x5, x6)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, NULL}
#define	CLIB_PLUGIN_NEEDED8(x0, x1, x2, x3, x4, x5, x6, x7)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, #x7, NULL}
#define	CLIB_PLUGIN_NEEDED9(x0, x1, x2, x3, x4, x5, x6, x7, x8)	\
const char *clib_plugin_needed[] = {#x0, #x1, #x2, #x3, #x4, #x5, #x6, #x7, #x8, NULL}

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
extern int clib_plugin_load(int argc, char *argv[]);
extern int clib_plugin_unload(int argc, char *argv[]);
extern int clib_plugin_reload(int argc, char *argv[]);
extern int clib_plugin_init_root(const char *dir);
extern int clib_plugin_load_default(struct clib_plugin_load_arg *s, int cnt);
extern void clib_plugin_cleanup(void);
extern void clib_plugin_print(void);
struct list_head *clib_plugin_get_head(void);
#define	CALL_FUNC_MAX_ARGS	9
extern long clib_plugin_call_func(const char *plugin_name,
				  const char *func_name,
				  int argc, ...);

/*
 * sometimes several plugins have the same exported symbol, use this macro
 * to call the specific plugin function, which means you should call with
 * `plugin_name`__`symbol_name`
 */
#define	CLIB_PLUGIN_CALL_FUNC_HEAD(plugin_name,ret_type,func_name,arg_list) \
static __maybe_unused ret_type plugin_name##__##func_name arg_list

#define	CLIB_PLUGIN_CALL_FUNC_TAIL(func_name,ret_type,arg_list) \
C_SYM ret_type func_name arg_list

#ifdef CLIB_PLUGIN_SYMBOL_CONFLICT

#define	CLIB_PLUGIN_CALL_FUNC0(plugin_name, func_name, ret_type) \
static __maybe_unused ret_type plugin_name##__##func_name (void)\
{\
return (ret_type)clib_plugin_call_func(#plugin_name,#func_name,0);\
}\
C_SYM ret_type func_name (void)

#define	CLIB_PLUGIN_CALL_FUNC(plugin_name, func_name, ret_type, arg_list, argc, ...) \
CLIB_PLUGIN_CALL_FUNC_HEAD(plugin_name,ret_type,func_name,arg_list)\
{\
return (ret_type)clib_plugin_call_func(#plugin_name,#func_name,argc,##__VA_ARGS__);\
}\
CLIB_PLUGIN_CALL_FUNC_TAIL(func_name,ret_type,arg_list)

#else	/* !CLIB_PLUGIN_SYMBOL_CONFLICT */

#define	CLIB_PLUGIN_CALL_FUNC0(plugin_name, func_name, ret_type) \
C_SYM ret_type func_name (void);\
static ret_type plugin_name##__##func_name (void) __attribute__((weakref,alias(#func_name)))

#define	CLIB_PLUGIN_CALL_FUNC(plugin_name, func_name, ret_type, arg_list, argc, ...) \
CLIB_PLUGIN_CALL_FUNC_TAIL(func_name,ret_type,arg_list);\
static ret_type plugin_name##__##func_name arg_list __attribute__((weakref,alias(#func_name)))

#endif

extern int clib_cmd_plugin_setup(struct clib_cmd *cs, int cs_cnt, char *plugin_root,
				 struct clib_plugin_load_arg *defplugin,
				 size_t plugin_cnt);

DECL_END

#endif /* end of include guard: PLUGIN_H_AOWIFXRV */
