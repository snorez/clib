#ifndef CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H
#define CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H

#include "../include/clib_utils.h"
#include "../include/clib_error.h"
#include "../include/clib_list.h"
#include "../include/clib_string.h"
#include <readline/readline.h>
#include <readline/history.h>

DECL_BEGIN

extern void clib_set_cmd_completor(void);
extern char *clib_readline_add_history(char *prompt);
extern int clib_cmd_add(char *buf);
extern void clib_cmd_del(char *buf);
extern void clib_cmd_cleanup(void);

DECL_END

#endif /* end of include guard: CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H */
