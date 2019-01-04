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
#include "../include/clib_string.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <setjmp.h>
#include <signal.h>

DECL_BEGIN

#define	CLIB_CMD_MAX	72
#define	CMD_ARGS_MAX	0x10
struct clib_cmd {
	char	*cmd;
	long	(*cb)(int argc, char **argv);
	void	(*usage)(void);
	ref_t	refcount;
};

extern void clib_set_cmd_completor(void);
extern char *clib_readline_add_history(char *prompt);
extern int clib_cmd_ac_add(char *buf);
extern void clib_cmd_ac_del(char *buf);
extern void clib_cmd_ac_cleanup(void);
extern struct clib_cmd *clib_cmd_find(char *name);
extern long clib_cmd_add(struct clib_cmd *newcmd);
extern long clib_cmd_add_array(struct clib_cmd *cs, int cs_cnt);
extern void clib_cmd_del(char *name);
extern void clib_cmd_cleanup(void);
extern long clib_cmd_exec(char *cmd, int argc, char **argv);
extern void clib_cmd_usages(void);
extern long clib_cmd_getarg(char *buf, size_t buflen, int *argc, char **argv);

DECL_END

#endif /* end of include guard: CLIB_CMD_AUTO_COMPLETION_H_PLTLGD8H */
