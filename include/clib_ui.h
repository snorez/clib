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
#ifndef CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H
#define CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H

#include "../include/clib_utils.h"
#include "../include/clib_atomic.h"
#include "../include/clib_error.h"
#include "../include/clib_list.h"
#include "../include/clib_buf.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <setjmp.h>
#include <signal.h>

DECL_BEGIN

#define	CLIB_UI_MAX_DEPTH	2
struct clib_ui_env {
	struct list_head	cmd_head;
	struct list_head	ac_head;
};

extern int clib_ui_begin(void);
extern void clib_ui_end(void);
extern char *clib_readline(char *prompt);

/* ac: auto complete */
extern int clib_ac_add(char *str);
extern void clib_ac_del(char *str);
extern void clib_ac_cleanup(void);

typedef long (*clib_cmd_cb)(int argc, char **argv);
typedef void (*clib_cmd_usage)(void);
struct clib_cmd {
	struct list_head	sibling;
	char			*cmd;
	clib_cmd_cb		cb;
	clib_cmd_usage		usage;
};

extern struct clib_cmd *clib_cmd_find(char *name);
extern long clib_cmd_add(char *name, clib_cmd_cb cb, clib_cmd_usage usage);
extern void clib_cmd_del(char *name);
extern void clib_cmd_cleanup(void);
extern long clib_cmd_exec(char *cmd, int argc, char **argv);
extern void clib_cmd_usages(void);
extern long clib_cmd_getarg(char *buf, size_t buflen,
				int *argc, char **argv, int argv_cnt);

extern long clib_cmd_ac_add(char *name, clib_cmd_cb cb, clib_cmd_usage usage);
extern void clib_cmd_ac_del(char *name);
extern void clib_cmd_ac_cleanup(void);

DECL_END

#endif /* end of include guard: CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H */
