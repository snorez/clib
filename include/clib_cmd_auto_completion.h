#ifndef CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H
#define CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H

#ifdef __cplusplus
extern "C" {
#endif

#include <readline/readline.h>
#include <readline/history.h>
#include "../include/clib_error.h"
#include "../include/clib_list.h"
#include "../include/clib_string.h"

extern void clib_set_cmd_completor(void);
extern char *clib_readline_add_history(char *prompt);
extern int clib_cmd_add(char *buf);
extern void clib_cmd_del(char *buf);
extern void clib_cmd_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H */
